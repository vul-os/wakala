package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/vul-os/vulos-relay/tunnel/internal/wire"
)

const controlPath = wire.ControlPath

// maintain runs the reconnect loop: dial -> register -> serve, then back off with
// jitter and retry until ctx is cancelled.
func (a *Agent) maintain(ctx context.Context) {
	backoff := 500 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		err := a.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.setStatus(StatusError, "", err.Error())
			a.appendLog("connection error: %v", err)
		} else {
			// Clean session end (server closed / stream loop ended); treat as retryable.
			a.setStatus(StatusStarting, "", "")
			a.appendLog("session ended; reconnecting")
		}

		// Exponential backoff with full jitter, capped.
		sleep := time.Duration(rand.Int63n(int64(backoff) + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		backoff *= 2
		if backoff > a.opts.MaxBackoff {
			backoff = a.opts.MaxBackoff
		}
	}
}

// connectOnce establishes one control connection, registers, and serves yamux
// streams until the session drops or ctx is cancelled.
func (a *Agent) connectOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, a.opts.HandshakeTimeout)
	defer cancel()

	conn, err := a.dial(dialCtx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Ensure the raw conn is closed when we leave (yamux also owns it, but this is
	// belt-and-suspenders for the error paths before yamux takes over).
	defer conn.Close()

	pub, err := a.register(conn)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	a.setStatus(StatusConnected, pub, "")
	a.appendLog("connected: public URL %s", pub)

	// The agent is the yamux SERVER (accepts streams the relay opens).
	session, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		return fmt.Errorf("yamux: %w", err)
	}
	defer session.Close()

	// Close the session if ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		session.Close()
	}()

	for {
		stream, err := session.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// io.EOF / session shutdown -> retryable clean end.
			if errors.Is(err, io.EOF) || errors.Is(err, yamux.ErrSessionShutdown) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go a.serveStream(stream)
	}
}

// dial opens the control websocket (or the test hook) and returns a net.Conn.
func (a *Agent) dial(ctx context.Context) (net.Conn, error) {
	if a.dialHook != nil {
		return a.dialHook(ctx)
	}
	target, err := controlURL(a.opts.ServerURL)
	if err != nil {
		return nil, err
	}

	tlsCfg := a.opts.TLSConfig
	if a.opts.InsecureSkipVerify {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		} else {
			tlsCfg = tlsCfg.Clone()
		}
		tlsCfg.InsecureSkipVerify = true
	}
	httpClient := &http.Client{}
	if tlsCfg != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	c, _, err := websocket.Dial(ctx, target, &websocket.DialOptions{
		Subprotocols: []string{wire.Subprotocol},
		HTTPHeader: http.Header{
			"Authorization": {"Bearer " + a.opts.Token},
		},
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, err
	}
	// Unlimited read: yamux frames + tunneled bodies can be large; the server caps
	// request/response sizes, and we cap the local dial. websocket.NetConn gives us
	// a net.Conn we can hand to yamux.
	c.SetReadLimit(-1)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// register performs the JSON handshake over the control conn and returns the
// assigned public URL.
func (a *Agent) register(conn net.Conn) (string, error) {
	_ = conn.SetDeadline(a.opts.now().Add(a.opts.HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	req := wire.Register{
		Type:         "register",
		Name:         a.opts.Name,
		Token:        a.opts.Token,
		AgentVersion: "vulos-relay-agent/0.1",
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return "", fmt.Errorf("write register: %w", err)
	}

	// Bounded read of the ack.
	dec := json.NewDecoder(io.LimitReader(conn, wire.MaxControlMessage))
	var ack wire.RegisterAck
	if err := dec.Decode(&ack); err != nil {
		return "", fmt.Errorf("read ack: %w", err)
	}
	if !ack.OK {
		msg := ack.Error
		if msg == "" {
			msg = "registration rejected"
		}
		return "", errors.New(msg)
	}
	return ack.PublicURL, nil
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	return c
}

// bufferedConn pairs a net.Conn with a Reader that may already hold buffered
// bytes (from bufio peeking), so downstream reads see the full stream.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func newBufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	return &bufferedConn{Conn: c, r: io.MultiReader(br, c)}
}
