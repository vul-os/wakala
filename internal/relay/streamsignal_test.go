// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// streamPair builds two stream peers (Client and Host) wired over an in-process
// LoopbackStreamTransport with mutual pinning. Returns the two relays, the
// loopback, and per-side inboxes that collect dispatched signals (so a test can
// assert SDP/ICE arrived on the other side).
func streamPair(t *testing.T) (client, host *StreamRelay, lb *LoopbackStreamTransport, clientInbox, hostInbox *inbox) {
	t.Helper()
	idC, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idH, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const domC, domH = "client.stream.local", "host.stream.local"

	resC := peering.NewStaticResolver()
	resH := peering.NewStaticResolver()
	descC := &peering.PeerDescriptor{Domains: []string{domC}, IdentityPub: idC.SignPub, KexPub: idC.KexPub, Versions: []string{peering.ProtoV1}, Suites: []string{peering.SuiteV1}, Endpoint: "ep-client"}
	descH := &peering.PeerDescriptor{Domains: []string{domH}, IdentityPub: idH.SignPub, KexPub: idH.KexPub, Versions: []string{peering.ProtoV1}, Suites: []string{peering.SuiteV1}, Endpoint: "ep-host"}
	for _, r := range []*peering.StaticResolver{resC, resH} {
		if err := r.Add(descC); err != nil {
			t.Fatal(err)
		}
		if err := r.Add(descH); err != nil {
			t.Fatal(err)
		}
	}

	clientInbox = newInbox()
	hostInbox = newInbox()
	lb = NewLoopbackStreamTransport()

	client = &StreamRelay{Identity: idC, Domain: domC, Resolver: resC, Transport: lb, Deliver: clientInbox.deliver}
	host = &StreamRelay{Identity: idH, Domain: domH, Resolver: resH, Transport: lb, Deliver: hostInbox.deliver}
	host.SetTURNEndpoint("relay.example:3478") // host plays "relay" role for fallback tests

	authC := func(d string) bool { return d == domC }
	authH := func(d string) bool { return d == domH }
	pinAll := func(d string) (ed25519.PublicKey, bool) {
		switch d {
		case domC:
			return idC.SignPub, true
		case domH:
			return idH.SignPub, true
		}
		return nil, false
	}
	lb.Register("ep-client", client, authC, pinAll)
	lb.Register("ep-host", host, authH, pinAll)
	return
}

// inbox captures dispatched StreamMessages on a relay's Deliver callback so
// tests can assert what was received over the signaling fabric.
type inbox struct {
	mu   sync.Mutex
	msgs []inboxEntry
}

type inboxEntry struct {
	from string
	msg  StreamMessage
}

func newInbox() *inbox { return &inbox{} }

func (i *inbox) deliver(from string, m StreamMessage) {
	i.mu.Lock()
	i.msgs = append(i.msgs, inboxEntry{from: from, msg: m})
	i.mu.Unlock()
}

func (i *inbox) snapshot() []inboxEntry {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]inboxEntry, len(i.msgs))
	copy(out, i.msgs)
	return out
}

// TestSDPICEExchange: client sends SDP offer → host inbox sees it; host sends
// SDP answer + ICE candidate → client inbox sees both. Pure signaling path,
// no TURN slot opened.
func TestSDPICEExchange(t *testing.T) {
	client, host, _, clientInbox, hostInbox := streamPair(t)

	const sid = "sess-1"
	offer := []byte("v=0\no=client\nm=video 9 UDP/TLS/RTP/SAVPF 96")
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamSDPOffer, Session: sid, SDP: offer,
	}); err != nil {
		t.Fatalf("client → host offer: %v", err)
	}
	answer := []byte("v=0\no=host\nm=video 9 UDP/TLS/RTP/SAVPF 96")
	if err := host.SendSignal(context.Background(), "client.stream.local", StreamMessage{
		Type: StreamSDPAnswer, Session: sid, SDP: answer,
	}); err != nil {
		t.Fatalf("host → client answer: %v", err)
	}
	cand := []byte("candidate:1 1 udp 2122252543 192.0.2.1 30000 typ host")
	if err := host.SendSignal(context.Background(), "client.stream.local", StreamMessage{
		Type: StreamICECand, Session: sid, Candidate: cand,
	}); err != nil {
		t.Fatalf("host → client ICE: %v", err)
	}

	// Host received the offer.
	hi := hostInbox.snapshot()
	if len(hi) != 1 || hi[0].msg.Type != StreamSDPOffer || !bytes.Equal(hi[0].msg.SDP, offer) {
		t.Fatalf("host inbox = %+v, want one SDPOffer", hi)
	}
	if hi[0].from != "client.stream.local" {
		t.Fatalf("host saw sender %q, want client.stream.local", hi[0].from)
	}

	// Client received both answer and ICE candidate.
	ci := clientInbox.snapshot()
	if len(ci) != 2 {
		t.Fatalf("client inbox = %d msgs, want 2: %+v", len(ci), ci)
	}
	if ci[0].msg.Type != StreamSDPAnswer || !bytes.Equal(ci[0].msg.SDP, answer) {
		t.Fatalf("client[0] = %+v, want SDPAnswer", ci[0])
	}
	if ci[1].msg.Type != StreamICECand || !bytes.Equal(ci[1].msg.Candidate, cand) {
		t.Fatalf("client[1] = %+v, want ICECand", ci[1])
	}

	// No TURN slot opened on the pure-signaling path.
	if snap := host.Snapshot(); snap.OpenSlots != 0 {
		t.Fatalf("TURN slot opened on pure signaling: %+v", snap)
	}
}

// TestSTUNBindingResponse: a well-formed STUN Binding Request gets a Success
// Response with the sender's XOR-MAPPED-ADDRESS. The function is pure so we
// drive it without a real socket.
func TestSTUNBindingResponse(t *testing.T) {
	// Build a Binding Request: type=0x0001, length=0, magic, txid.
	req := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:2], stunMethodBinding|stunClassRequest)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	for i := 0; i < 12; i++ {
		req[8+i] = byte(i + 1)
	}

	from := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 49222}
	resp := HandleSTUNPacket(req, from)
	if resp == nil {
		t.Fatal("HandleSTUNPacket returned nil for valid Binding Request")
	}
	if len(resp) < stunHeaderLen+12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	mtype := binary.BigEndian.Uint16(resp[0:2])
	if mtype != (stunClassSuccessResponse | stunMethodBinding) {
		t.Fatalf("response msg type = 0x%04x, want 0x%04x", mtype, stunClassSuccessResponse|stunMethodBinding)
	}
	if binary.BigEndian.Uint32(resp[4:8]) != stunMagicCookie {
		t.Fatal("response missing magic cookie")
	}
	// txid echoed.
	for i := 0; i < 12; i++ {
		if resp[8+i] != byte(i+1) {
			t.Fatalf("txid byte %d mismatch", i)
		}
	}
	// Attribute: XOR-MAPPED-ADDRESS.
	attrType := binary.BigEndian.Uint16(resp[20:22])
	if attrType != stunAttrXORMappedAddress {
		t.Fatalf("attr type = 0x%04x, want 0x%04x", attrType, stunAttrXORMappedAddress)
	}
	attrLen := binary.BigEndian.Uint16(resp[22:24])
	if attrLen != 8 {
		t.Fatalf("attr len = %d, want 8", attrLen)
	}
	if resp[24] != 0 || resp[25] != stunFamilyIPv4 {
		t.Fatalf("attr family bytes = %02x %02x, want 00 01", resp[24], resp[25])
	}
	xport := binary.BigEndian.Uint16(resp[26:28])
	gotPort := int(xport ^ uint16(stunMagicCookie>>16))
	if gotPort != from.Port {
		t.Fatalf("decoded port = %d, want %d", gotPort, from.Port)
	}
	var cookieBytes [4]byte
	binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
	var gotIP [4]byte
	for i := 0; i < 4; i++ {
		gotIP[i] = resp[28+i] ^ cookieBytes[i]
	}
	wantIP := from.IP.To4()
	for i := 0; i < 4; i++ {
		if gotIP[i] != wantIP[i] {
			t.Fatalf("decoded IP byte %d = %d, want %d", i, gotIP[i], wantIP[i])
		}
	}
}

// TestSTUNRejectsNonBinding: non-Binding packets and bad cookies are silently
// dropped (returns nil).
func TestSTUNRejectsNonBinding(t *testing.T) {
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	if HandleSTUNPacket(nil, from) != nil {
		t.Fatal("nil pkt should drop")
	}
	if HandleSTUNPacket(make([]byte, 5), from) != nil {
		t.Fatal("short pkt should drop")
	}
	bad := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(bad[0:2], stunMethodBinding|stunClassRequest)
	binary.BigEndian.PutUint32(bad[4:8], 0xdeadbeef) // wrong magic
	if HandleSTUNPacket(bad, from) != nil {
		t.Fatal("bad-magic pkt should drop")
	}
	// Right magic but wrong method.
	other := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(other[0:2], 0x0003 /* Allocate */) // not Binding
	binary.BigEndian.PutUint32(other[4:8], stunMagicCookie)
	if HandleSTUNPacket(other, from) != nil {
		t.Fatal("non-binding method should drop")
	}
}

// TestTURNFallbackGatedOnP2PFailure: no TURN slot exists until msgP2PFailed
// arrives; on receipt, the relay opens a slot and acks with the published
// endpoint. Pure SDP/ICE never opens a slot. Verifies the gate.
func TestTURNFallbackGatedOnP2PFailure(t *testing.T) {
	client, host, _, clientInbox, _ := streamPair(t)

	const sid = "sess-fb"
	// Pure SDP: no slot.
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamSDPOffer, Session: sid, SDP: []byte("v=0"),
	}); err != nil {
		t.Fatal(err)
	}
	if snap := host.Snapshot(); snap.OpenSlots != 0 || snap.FallbacksTotal != 0 {
		t.Fatalf("slot opened without P2P-failure signal: %+v", snap)
	}

	// Now signal P2P failure.
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamP2PFailed, Session: sid, Reason: []byte("ice-failed"),
	}); err != nil {
		t.Fatal(err)
	}
	snap := host.Snapshot()
	if snap.OpenSlots != 1 {
		t.Fatalf("expected 1 open TURN slot, got %d", snap.OpenSlots)
	}
	if snap.FallbacksTotal != 1 {
		t.Fatalf("expected fallback count 1, got %d", snap.FallbacksTotal)
	}
	if snap.FallbackRate <= 0 || snap.FallbackRate > 1 {
		t.Fatalf("fallback rate out of (0,1]: %v", snap.FallbackRate)
	}

	// The client should have received a TURN ack carrying the endpoint.
	var ack *StreamMessage
	for _, e := range clientInbox.snapshot() {
		if e.msg.Type == StreamTURNAck && e.msg.Session == sid {
			m := e.msg
			ack = &m
			break
		}
	}
	if ack == nil {
		t.Fatal("client never received TURN ack")
	}
	if ack.Endpoint != "relay.example:3478" {
		t.Fatalf("ack endpoint = %q, want relay.example:3478", ack.Endpoint)
	}
	if len(ack.Token) == 0 {
		t.Fatal("ack token empty")
	}

	// Closing the slot drops it.
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamTURNClose, Session: sid,
	}); err != nil {
		t.Fatal(err)
	}
	if snap := host.Snapshot(); snap.OpenSlots != 0 {
		t.Fatalf("slot not closed: %+v", snap)
	}
}

// TestTURNMediaRelayDeniedWithoutSlot: RelayMediaInbound rejects packets for a
// session that has no open slot — proving "always-on" is impossible.
func TestTURNMediaRelayDeniedWithoutSlot(t *testing.T) {
	_, host, _, _, _ := streamPair(t)
	from := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	if _, err := host.RelayMediaInbound("no-such-session", from, 100); err == nil {
		t.Fatal("expected error when relaying without an open slot")
	}
}

// TestTURNEgressAccounting: with a slot open, two distinct sources have media
// bridged and bytes are metered. Quota exhaustion closes the slot.
func TestTURNEgressAccounting(t *testing.T) {
	_, host, _, _, _ := streamPair(t)
	host.DefaultSlotQuotaBytes = 10_000 // cap egress for the quota assertion

	const sid = "sess-bytes"
	// Open the slot the same way a P2P-failure signal would: via the public
	// flow.
	client, _, _, _, _ := streamPair(t) // separate pair just for a sender identity isn't needed; reuse host as-is
	_ = client                          // suppress unused
	// Use the explicit, internal API instead so we don't need a second pair.
	host.openSlot(sid)

	srcA := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 4000}
	srcB := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 11), Port: 4001}

	// First packet from A: bridge not yet established (no dst), bytes still
	// metered as bytesIn.
	dst, err := host.RelayMediaInbound(sid, srcA, 100)
	if err != nil {
		t.Fatalf("relay A: %v", err)
	}
	if dst != nil {
		t.Fatalf("unexpected dst before B registered: %v", dst)
	}
	in, out, ok := host.SlotEgress(sid)
	if !ok || in != 100 || out != 0 {
		t.Fatalf("after A: in=%d out=%d ok=%v, want 100/0/true", in, out, ok)
	}

	// First packet from B: bridge now established; A's addr is returned as
	// dst, and both directions are accounted (200 bytes total this call).
	dst, err = host.RelayMediaInbound(sid, srcB, 200)
	if err != nil {
		t.Fatalf("relay B: %v", err)
	}
	if dst == nil || dst.String() != srcA.String() {
		t.Fatalf("expected bridge to A, got %v", dst)
	}
	in, out, _ = host.SlotEgress(sid)
	if in != 300 || out != 200 {
		t.Fatalf("after B: in=%d out=%d, want 300/200", in, out)
	}

	// Quota exhaustion: ask for a huge packet beyond the cap.
	if _, err := host.RelayMediaInbound(sid, srcA, 100_000); err == nil {
		t.Fatal("expected egress quota exhaustion")
	}
	// Slot is now closed.
	if _, _, ok := host.SlotEgress(sid); ok {
		t.Fatal("slot should be closed after quota exhaustion")
	}
}

// TestIdempotentReSignaling: re-sending the same SDP for a session must not
// open additional TURN slots or otherwise mutate relay state in a way that
// matters. The receiver's Deliver hook sees both copies (the application
// owns dedup) but the relay's open-slots count stays at zero.
func TestIdempotentReSignaling(t *testing.T) {
	client, host, _, _, _ := streamPair(t)

	const sid = "sess-re"
	offer := []byte("v=0 retransmit")
	for i := 0; i < 3; i++ {
		// Each call uses a fresh envelope (peering's §7 replay window keys on
		// nonce, and Seal generates a fresh nonce each call), so re-sending
		// the same application-level message is a real wire send.
		if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
			Type: StreamSDPOffer, Session: sid, SDP: offer,
		}); err != nil {
			t.Fatalf("re-send %d: %v", i, err)
		}
	}
	if snap := host.Snapshot(); snap.OpenSlots != 0 {
		t.Fatalf("re-signaling opened a slot: %+v", snap)
	}

	// Re-issuing the P2P-failure signal for the SAME session must refresh
	// rather than duplicate slots. (The slot count stays at 1.)
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamP2PFailed, Session: sid,
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamP2PFailed, Session: sid,
	}); err != nil {
		t.Fatal(err)
	}
	if snap := host.Snapshot(); snap.OpenSlots != 1 {
		t.Fatalf("re-fallback opened multiple slots: %+v", snap)
	}
}

// TestStreamRejectsUnpinnedSender: a signaling envelope from an unpinned
// domain is rejected by the reused peering §8 checks — no from-scratch crypto.
func TestStreamRejectsUnpinnedSender(t *testing.T) {
	client, _, lb, _, _ := streamPair(t)
	// Re-register the host endpoint with a pinning oracle that knows nobody.
	id, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	res := peering.NewStaticResolver()
	bogus := &StreamRelay{Identity: id, Domain: "host.stream.local", Resolver: res, Transport: lb}
	bogus.init()
	lb.Register("ep-host", bogus, func(string) bool { return true }, func(string) (ed25519.PublicKey, bool) { return nil, false })

	err = client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamSDPOffer, Session: "x", SDP: []byte("v=0"),
	})
	if err == nil {
		t.Fatal("expected signaling to fail against an endpoint that pins nobody")
	}
}

// TestSignalMarshalRoundTrip: every msg type survives the codec verbatim and
// trailing junk is rejected.
func TestSignalMarshalRoundTrip(t *testing.T) {
	cases := []*signalMsg{
		{typ: msgSDPOffer, session: "s1", sdp: []byte("offer")},
		{typ: msgSDPAnswer, session: "s2", sdp: []byte("answer")},
		{typ: msgICECand, session: "s3", candidate: []byte("cand")},
		{typ: msgP2PFailed, session: "s4", reason: []byte("ice-failed")},
		{typ: msgTURNAck, session: "s5", token: []byte("tok"), endpoint: "r:3478"},
		{typ: msgTURNClose, session: "s6"},
	}
	for _, want := range cases {
		wire := marshalSignal(want)
		got, err := unmarshalSignal(wire)
		if err != nil {
			t.Fatalf("unmarshal %d: %v", want.typ, err)
		}
		if got.typ != want.typ || got.session != want.session ||
			!bytes.Equal(got.sdp, want.sdp) || !bytes.Equal(got.candidate, want.candidate) ||
			!bytes.Equal(got.reason, want.reason) || !bytes.Equal(got.token, want.token) ||
			got.endpoint != want.endpoint {
			t.Fatalf("round-trip mismatch type %d: %+v vs %+v", want.typ, got, want)
		}
		if _, err := unmarshalSignal(append(wire, 0xff)); err == nil {
			t.Fatalf("trailing junk accepted for type %d", want.typ)
		}
	}
	if _, err := unmarshalSignal([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestFallbackRatioMetric: the per-relay FallbackRate matches what the
// Prometheus gauge would report (fallbacks / signals).
func TestFallbackRatioMetric(t *testing.T) {
	client, host, _, _, _ := streamPair(t)
	const sid = "sess-ratio"

	// Five pure-signaling sends + one P2P failure ⇒ 1/6 ratio at the host.
	for i := 0; i < 5; i++ {
		if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
			Type: StreamSDPOffer, Session: sid, SDP: []byte("v=0"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SendSignal(context.Background(), "host.stream.local", StreamMessage{
		Type: StreamP2PFailed, Session: sid,
	}); err != nil {
		t.Fatal(err)
	}
	snap := host.Snapshot()
	if snap.SignalsTotal == 0 {
		t.Fatal("no signals counted on host")
	}
	want := float64(snap.FallbacksTotal) / float64(snap.SignalsTotal)
	if host.FallbackRate() != want {
		t.Fatalf("FallbackRate() = %v, want %v", host.FallbackRate(), want)
	}
}

// TestSTUNServeUnreachable: ServeSTUN should return promptly when its context
// is cancelled even with no traffic. We don't bind a public port in CI.
func TestSTUNServeUnreachable(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("loopback UDP listen unavailable in this env: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = ServeSTUN(ctx, conn); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeSTUN did not return after ctx cancel")
	}
}

// Compile-time assertions for the seams.
var (
	_ peering.PeerTransport = (*LoopbackStreamTransport)(nil)
	_ SyncResponder         = (*LoopbackStreamTransport)(nil)
)
