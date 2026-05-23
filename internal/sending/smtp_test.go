// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// smtpSink is a minimal SMTP sink server for testing.  It speaks just enough
// SMTP to let net/smtp complete a transaction.
type smtpSink struct {
	ln      net.Listener
	handler func(conn net.Conn) // optional: override per-connection behaviour
}

// newSMTPSink starts a localhost SMTP sink.
func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	s := &smtpSink{ln: ln}
	go s.serve()
	return s
}

func (s *smtpSink) addr() string { return s.ln.Addr().String() }

func (s *smtpSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if s.handler != nil {
			go s.handler(conn)
		} else {
			go s.defaultHandle(conn)
		}
	}
}

func (s *smtpSink) close() { _ = s.ln.Close() }

// defaultHandle speaks minimal SMTP and accepts everything.
func (s *smtpSink) defaultHandle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(line string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}

	writeLine("220 sink.test ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			writeLine("250-sink.test")
			writeLine("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"):
			writeLine("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			writeLine("250 OK")
		case upper == "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				data, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if strings.TrimRight(data, "\r\n") == "." {
					break
				}
			}
			writeLine("250 OK: queued")
		case strings.HasPrefix(upper, "QUIT"):
			writeLine("221 Bye")
			return
		default:
			writeLine("500 unknown command")
		}
	}
}

// reject550Handle sends a 550 rejection at RCPT TO.
func reject550Handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(line string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}

	writeLine("220 sink.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			writeLine("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"):
			writeLine("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			writeLine("550 5.1.1 User unknown")
			return
		default:
			writeLine("500 unknown")
		}
	}
}

// defer421Handle sends a 421 at MAIL FROM.
func defer421Handle(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(line string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}

	writeLine("220 sink.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			writeLine("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"):
			writeLine("421 4.7.0 Try later")
			return
		default:
			writeLine("500 unknown")
		}
	}
}

// fixedMXResolver always returns a single MX pointing at the given host:port.
type fixedMXResolver struct{ host string }

func (r fixedMXResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return []*net.MX{{Host: r.host, Pref: 10}}, nil
}

// fixedDialer always dials the given address regardless of the requested addr.
type fixedDialer struct{ addr string }

func (d fixedDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr)
}

func smtpSenderForSink(sink *smtpSink) *sending.SMTPSender {
	host, port, _ := net.SplitHostPort(sink.addr())
	_ = port
	return &sending.SMTPSender{
		DNSResolver: fixedMXResolver{host: host},
		Dialer:      fixedDialer{addr: sink.addr()},
	}
}

// TestSMTPSenderDelivered checks that the SMTPSender returns StateDelivered on
// a successful transaction with the stub SMTP sink.
func TestSMTPSenderDelivered(t *testing.T) {
	sink := newSMTPSink(t)
	defer sink.close()

	s := smtpSenderForSink(sink)

	msg := sending.Message{
		ID:         "test-1",
		AccountID:  "acct1",
		Sender:     "from@example.com",
		Recipients: []string{"to@example.org"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nbody"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if result.State != sending.StateDelivered {
		t.Errorf("expected StateDelivered, got %s (code %d, msg: %s)", result.State, result.Code, result.Message)
	}
}

// TestSMTPSenderBounced checks that a 550 at RCPT TO is classified as StateBounced.
func TestSMTPSenderBounced(t *testing.T) {
	sink := newSMTPSink(t)
	sink.handler = reject550Handle
	defer sink.close()

	s := smtpSenderForSink(sink)

	msg := sending.Message{
		ID:         "test-2",
		Sender:     "from@example.com",
		Recipients: []string{"bad@example.org"},
		RawRFC822:  []byte("Subject: bounce test\r\n\r\nbody"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != sending.StateBounced {
		t.Errorf("expected StateBounced, got %s (code %d)", result.State, result.Code)
	}
}

// TestSMTPSenderDeferred checks that a 421 is classified as StateDeferred.
func TestSMTPSenderDeferred(t *testing.T) {
	sink := newSMTPSink(t)
	sink.handler = defer421Handle
	defer sink.close()

	s := smtpSenderForSink(sink)

	msg := sending.Message{
		ID:         "test-3",
		Sender:     "from@example.com",
		Recipients: []string{"to@example.org"},
		RawRFC822:  []byte("Subject: defer test\r\n\r\nbody"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != sending.StateDeferred {
		t.Errorf("expected StateDeferred, got %s (code %d)", result.State, result.Code)
	}
}

// TestSMTPSenderNoRecipients verifies that a message with no recipients is
// classified as a bounce immediately.
func TestSMTPSenderNoRecipients(t *testing.T) {
	s := &sending.SMTPSender{}
	msg := sending.Message{
		ID:        "test-4",
		Sender:    "from@example.com",
		RawRFC822: []byte("Subject: no rcpt\r\n\r\nbody"),
	}
	result, err := s.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != sending.StateBounced {
		t.Errorf("expected StateBounced for no recipients, got %s", result.State)
	}
}

// TestSMTPSenderDialFailureDeferred checks that a dial failure is treated as
// a transient (deferred) infrastructure error.
func TestSMTPSenderDialFailureDeferred(t *testing.T) {
	s := &sending.SMTPSender{
		DNSResolver: fixedMXResolver{host: "127.0.0.1"},
		// Dialer tries to connect to a port that nothing listens on.
		Dialer: fixedDialer{addr: "127.0.0.1:1"}, // port 1 almost certainly refused
	}

	msg := sending.Message{
		ID:         "test-5",
		Sender:     "from@example.com",
		Recipients: []string{"to@nowhere.test"},
		RawRFC822:  []byte("Subject: infra fail\r\n\r\nbody"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, _ := s.Send(ctx, msg)
	if result.State != sending.StateDeferred {
		t.Errorf("expected StateDeferred for dial failure, got %s", result.State)
	}
}
