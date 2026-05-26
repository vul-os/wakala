// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// ── fake DNSSEC resolver ───────────────────────────────────────────────────

// fakeDANEResolver is a fake sending.DNSSECResolver: it returns a fixed TLSA
// result for any MX, simulating a DNSSEC-validated (or not) answer.
type fakeDANEResolver struct {
	result sending.TLSAResult
	err    error
}

func (f fakeDANEResolver) LookupTLSA(_ context.Context, _ string) (sending.TLSAResult, error) {
	return f.result, f.err
}

// ── TLS-capable SMTP sink with a self-signed cert ──────────────────────────

// tlsSink is a minimal SMTP sink that performs a REAL STARTTLS handshake using
// a self-signed certificate, then captures the DATA payload. It lets a DANE
// test compute a TLSA association from the exact cert the sink presents.
type tlsSink struct {
	ln   net.Listener
	cert tls.Certificate
	leaf *x509.Certificate

	mu        sync.Mutex
	data      string
	tlsOK     bool
	dataAfter bool // whether DATA arrived after TLS
}

func newTLSSink(t *testing.T) *tlsSink {
	t.Helper()
	cert, leaf := selfSignedCert(t, "mx.test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &tlsSink{ln: ln, cert: cert, leaf: leaf}
	go s.serve()
	return s
}

func (s *tlsSink) addr() string { return s.ln.Addr().String() }
func (s *tlsSink) close()       { _ = s.ln.Close() }

func (s *tlsSink) captured() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *tlsSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *tlsSink) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(line string) {
		_, _ = fmt.Fprintf(w, "%s\r\n", line)
		_ = w.Flush()
	}
	write("220 mx.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-mx.test")
			write("250 STARTTLS")
		case strings.HasPrefix(upper, "STARTTLS"):
			write("220 Go ahead")
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{s.cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			s.mu.Lock()
			s.tlsOK = true
			s.mu.Unlock()
			// Continue the SMTP conversation over TLS.
			r = bufio.NewReader(tlsConn)
			w = bufio.NewWriter(tlsConn)
			write = func(line string) {
				_, _ = fmt.Fprintf(w, "%s\r\n", line)
				_ = w.Flush()
			}
		case strings.HasPrefix(upper, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			write("250 OK")
		case upper == "DATA":
			write("354 End data")
			var b strings.Builder
			for {
				d, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if strings.TrimRight(d, "\r\n") == "." {
					break
				}
				b.WriteString(d)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			write("250 OK queued")
		case strings.HasPrefix(upper, "QUIT"):
			write("221 Bye")
			return
		default:
			write("500 unknown")
		}
	}
}

// selfSignedCert returns a fresh self-signed ECDSA cert for cn.
func selfSignedCert(t *testing.T, cn string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// tlsaFor computes a DANE-EE TLSA record (usage 3) for cert using selector 1
// (SPKI) + matching type 1 (SHA-256), the most common SMTP DANE-EE form.
func tlsaFor(t *testing.T, cert *x509.Certificate) sending.TLSARecord {
	t.Helper()
	assoc, err := dns.CertificateToDANE(1, 1, cert) // selector=SPKI, match=SHA-256
	if err != nil {
		t.Fatalf("CertificateToDANE: %v", err)
	}
	return sending.TLSARecord{Usage: 3, Selector: 1, MatchingType: 1, Cert: assoc}
}

// ── tests ──────────────────────────────────────────────────────────────────

// TestDANEMatchEnforcesTLSAndDelivers proves that when a DNSSEC-validated TLSA
// record matches the MX's presented cert, TLS is used and the message is
// delivered.
func TestDANEMatchEnforcesTLSAndDelivers(t *testing.T) {
	sink := newTLSSink(t)
	defer sink.close()

	rec := tlsaFor(t, sink.leaf)
	host, _, _ := net.SplitHostPort(sink.addr())

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		// Secure=true → DNSSEC-validated; matching record present.
		DANE: fakeDANEResolver{result: sending.TLSAResult{Records: []sending.TLSARecord{rec}, Secure: true}},
		// Even opportunistic TLS policy must be overridden to mandatory by DANE.
		TLSPolicy: sending.TLSPolicyOpportunistic,
	}

	msg := sending.Message{
		ID:         "dane-match",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("DANE match: want delivered, got %s (%s)", res.State, res.Message)
	}
	sink.mu.Lock()
	tlsOK := sink.tlsOK
	sink.mu.Unlock()
	if !tlsOK {
		t.Fatalf("DANE match: message delivered without completing TLS handshake")
	}
	if got := sink.captured(); !strings.Contains(got, "body") {
		t.Fatalf("DANE match: DATA not received over TLS:\n%q", got)
	}
}

// TestDANEMismatchDefersNeverPlaintext proves that when the TLSA record does NOT
// match the MX cert, the message is DEFERRED and never delivered (no plaintext
// fallback).
func TestDANEMismatchDefersNeverPlaintext(t *testing.T) {
	sink := newTLSSink(t)
	defer sink.close()

	// A TLSA record for a DIFFERENT cert → will not match the sink's leaf.
	_, otherLeaf := selfSignedCert(t, "evil.test")
	rec := tlsaFor(t, otherLeaf)
	host, _, _ := net.SplitHostPort(sink.addr())

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		DANE:        fakeDANEResolver{result: sending.TLSAResult{Records: []sending.TLSARecord{rec}, Secure: true}},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
	}

	msg := sending.Message{
		ID:         "dane-mismatch",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("DANE mismatch: want StateDeferred, got %s (%s)", res.State, res.Message)
	}
	// Must NOT have delivered the message (no DATA captured).
	if got := sink.captured(); got != "" {
		t.Fatalf("DANE mismatch: message was delivered despite TLSA mismatch:\n%q", got)
	}
}

// TestDANEUnvalidatedTreatedAsAbsent proves that TLSA records returned WITHOUT a
// DNSSEC-validated (Secure) answer are ignored — fail safe (RFC 7672 §2.1).
func TestDANEUnvalidatedTreatedAsAbsent(t *testing.T) {
	// A plain sink (no STARTTLS). With DANE ignored AND an opportunistic TLS
	// policy, delivery proceeds in plaintext — proving the (mismatching) TLSA
	// record was NOT acted on because the answer was not DNSSEC-validated.
	sink := newCapturingSink(t, false)
	defer sink.close()

	// A mismatching record, but Secure=false → must be ignored entirely.
	_, otherLeaf := selfSignedCert(t, "evil.test")
	rec := tlsaFor(t, otherLeaf)
	host, _, _ := net.SplitHostPort(sink.addr())

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		DANE:        fakeDANEResolver{result: sending.TLSAResult{Records: []sending.TLSARecord{rec}, Secure: false}},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
	}

	msg := sending.Message{
		ID:         "dane-unvalidated",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.State != sending.StateDelivered {
		t.Fatalf("unvalidated TLSA: want delivered (DANE ignored), got %s (%s)", res.State, res.Message)
	}
}

// TestDANESecuredButNoSTARTTLSDefers proves that a DANE-secured MX that does not
// offer STARTTLS defers rather than delivering in plaintext.
func TestDANESecuredButNoSTARTTLSDefers(t *testing.T) {
	// A plain sink that never advertises STARTTLS.
	sink := newCapturingSink(t, false)
	defer sink.close()

	_, leaf := selfSignedCert(t, "mx.test")
	rec := tlsaFor(t, leaf)
	host, _, _ := net.SplitHostPort(sink.addr())

	s := &sending.SMTPSender{
		DNSResolver: fixedMX{host: host},
		Dialer:      fixedDialer2{addr: sink.addr()},
		DANE:        fakeDANEResolver{result: sending.TLSAResult{Records: []sending.TLSARecord{rec}, Secure: true}},
		TLSPolicy:   sending.TLSPolicyOpportunistic,
	}

	msg := sending.Message{
		ID:         "dane-no-starttls",
		Sender:     "alice@example.com",
		Recipients: []string{"bob@example.org"},
		RawRFC822:  []byte("From: alice@example.com\r\n\r\nbody\r\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := s.Send(ctx, msg)
	if res.State != sending.StateDeferred {
		t.Fatalf("DANE no-STARTTLS: want StateDeferred, got %s (%s)", res.State, res.Message)
	}
	if got := sink.captured(); got != "" {
		t.Fatalf("DANE no-STARTTLS: delivered in plaintext despite DANE:\n%q", got)
	}
}
