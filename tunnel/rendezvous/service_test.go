package rendezvous

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── test harness ─────────────────────────────────────────────────────────────

type testEnv struct {
	svc *Service
	ts  *httptest.Server
	now func() time.Time
}

func newTestEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	cfg.now = clock.now
	svc := New(cfg)
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{svc: svc, ts: ts, now: clock.now}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, b64.EncodeToString(pub)
}

var nonceCounter atomic.Int64

func freshNonce() string {
	n := nonceCounter.Add(1)
	return b64.EncodeToString([]byte("nonce-" + strconv.FormatInt(n, 10) + "-padpadpadpad"))
}

func (e *testEnv) post(t *testing.T, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(e.ts.URL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

func (e *testEnv) get(t *testing.T, path string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Get(e.ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

// signed request builders --------------------------------------------------

func (e *testEnv) announce(priv ed25519.PrivateKey, keyB64 string, eps []string, meta string, ttl int) announceRequest {
	req := announceRequest{Key: keyB64, Endpoints: eps, Meta: meta, TTL: ttl, Nonce: freshNonce(), Timestamp: e.now().Unix()}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, announceSigningMessage(&req)))
	return req
}

func (e *testEnv) deposit(domain string, priv ed25519.PrivateKey, from, to, payloadB64 string, ttl int) depositRequest {
	req := depositRequest{From: from, To: to, Payload: payloadB64, TTL: ttl, Nonce: freshNonce(), Timestamp: e.now().Unix()}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, depositSigningMessage(domain, &req)))
	return req
}

func (e *testEnv) poll(domain string, priv ed25519.PrivateKey, keyB64 string, wait int) pollRequest {
	req := pollRequest{Key: keyB64, Nonce: freshNonce(), Timestamp: e.now().Unix(), Wait: wait}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, pollSigningMessage(domain, &req)))
	return req
}

func (e *testEnv) ack(domain string, priv ed25519.PrivateKey, keyB64 string, ids []string) ackRequest {
	req := ackRequest{Key: keyB64, IDs: ids, Nonce: freshNonce(), Timestamp: e.now().Unix()}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, ackSigningMessage(domain, &req)))
	return req
}

// ── ANNOUNCE / RESOLVE ───────────────────────────────────────────────────────

func TestAnnounceResolveRoundTrip(t *testing.T) {
	e := newTestEnv(t, Config{})
	pub, priv, key := genKey(t)
	_ = pub

	resp, out := e.post(t, "/rendezvous/announce", e.announce(priv, key, []string{"wss://box.example/tunnel", "https://1.2.3.4:443"}, "caps=chat,files", 300))
	if resp.StatusCode != 200 {
		t.Fatalf("announce status=%d body=%v", resp.StatusCode, out)
	}
	if out["ok"] != true || out["key"] != key {
		t.Fatalf("announce response: %v", out)
	}

	resp, out = e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 200 {
		t.Fatalf("resolve status=%d body=%v", resp.StatusCode, out)
	}
	if out["online"] != true {
		t.Fatalf("expected online: %v", out)
	}
	eps, _ := out["endpoints"].([]any)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %v", out["endpoints"])
	}
	if out["meta"] != "caps=chat,files" {
		t.Fatalf("meta mismatch: %v", out["meta"])
	}
}

func TestResolveUnknownKey404(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, _, key := genKey(t)
	resp, out := e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 404 || out["online"] != false {
		t.Fatalf("expected 404 offline, got %d %v", resp.StatusCode, out)
	}
}

func TestAnnounceBadSignatureRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, priv, key := genKey(t)
	req := e.announce(priv, key, []string{"wss://x"}, "", 300)
	req.Sig = b64.EncodeToString(make([]byte, sigLen)) // wrong sig
	resp, out := e.post(t, "/rendezvous/announce", req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d %v", resp.StatusCode, out)
	}
	// And nothing was stored.
	resp, _ = e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 404 {
		t.Fatalf("bad-sig announce must not store presence, got %d", resp.StatusCode)
	}
}

func TestAnnounceSignedByWrongKeyRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, _, key := genKey(t)
	_, otherPriv, _ := genKey(t)
	// Claim `key` but sign with a different private key.
	req := announceRequest{Key: key, Endpoints: []string{"wss://x"}, Nonce: freshNonce(), Timestamp: e.now().Unix(), TTL: 300}
	req.Sig = b64.EncodeToString(ed25519.Sign(otherPriv, announceSigningMessage(&req)))
	resp, _ := e.post(t, "/rendezvous/announce", req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong-key sig, got %d", resp.StatusCode)
	}
}

func TestAnnounceReplayRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, priv, key := genKey(t)
	req := e.announce(priv, key, []string{"wss://x"}, "", 300)
	resp, _ := e.post(t, "/rendezvous/announce", req)
	if resp.StatusCode != 200 {
		t.Fatalf("first announce failed: %d", resp.StatusCode)
	}
	// Exact same signed request again => replayed nonce.
	resp, out := e.post(t, "/rendezvous/announce", req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 replay, got %d %v", resp.StatusCode, out)
	}
}

func TestAnnounceStaleTimestampRejected(t *testing.T) {
	e := newTestEnv(t, Config{ClockSkew: time.Minute})
	_, priv, key := genKey(t)
	req := announceRequest{Key: key, Endpoints: []string{"wss://x"}, Nonce: freshNonce(), Timestamp: e.now().Add(-10 * time.Minute).Unix(), TTL: 300}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, announceSigningMessage(&req)))
	resp, out := e.post(t, "/rendezvous/announce", req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for stale ts, got %d %v", resp.StatusCode, out)
	}
}

func TestPresenceTTLExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := New(Config{now: clock.now})
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()
	e := &testEnv{svc: svc, ts: ts, now: clock.now}

	_, priv, key := genKey(t)
	e.post(t, "/rendezvous/announce", e.announce(priv, key, []string{"wss://x"}, "", 60))
	resp, _ := e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 200 {
		t.Fatalf("should be online")
	}
	clock.advance(2 * time.Minute)
	resp, _ = e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 404 {
		t.Fatalf("expected expiry 404, got %d", resp.StatusCode)
	}
}

func TestWithdraw(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, priv, key := genKey(t)
	e.post(t, "/rendezvous/announce", e.announce(priv, key, []string{"wss://x"}, "", 300))
	req := withdrawRequest{Key: key, Nonce: freshNonce(), Timestamp: e.now().Unix()}
	req.Sig = b64.EncodeToString(ed25519.Sign(priv, withdrawSigningMessage(&req)))
	resp, _ := e.post(t, "/rendezvous/withdraw", req)
	if resp.StatusCode != 200 {
		t.Fatalf("withdraw failed: %d", resp.StatusCode)
	}
	resp, _ = e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 after withdraw, got %d", resp.StatusCode)
	}
}

func TestDisablePublicResolve(t *testing.T) {
	e := newTestEnv(t, Config{DisablePublicResolve: true})
	_, priv, key := genKey(t)
	e.post(t, "/rendezvous/announce", e.announce(priv, key, []string{"wss://x"}, "", 300))
	resp, out := e.get(t, "/rendezvous/resolve/"+key)
	if resp.StatusCode != 404 || out["online"] != false {
		t.Fatalf("resolve should be closed, got %d %v", resp.StatusCode, out)
	}
}

// ── SIGNAL deposit / poll / ack ──────────────────────────────────────────────

func TestSignalDepositPollAck(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, senderPriv, sender := genKey(t)
	_, rcptPriv, rcpt := genKey(t)

	payload := b64.EncodeToString([]byte("opaque-offer-sdp"))
	resp, out := e.post(t, "/rendezvous/signal/"+rcpt, e.deposit(domainSignalDeposit, senderPriv, sender, rcpt, payload, 0))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deposit status=%d body=%v", resp.StatusCode, out)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("no id returned: %v", out)
	}

	// Recipient polls.
	resp, out = e.post(t, "/rendezvous/signal/"+rcpt+"/poll", e.poll(domainSignalPoll, rcptPriv, rcpt, 0))
	if resp.StatusCode != 200 {
		t.Fatalf("poll status=%d", resp.StatusCode)
	}
	blobs, _ := out["blobs"].([]any)
	if len(blobs) != 1 {
		t.Fatalf("expected 1 blob, got %v", out["blobs"])
	}
	b0 := blobs[0].(map[string]any)
	if b0["payload"] != payload || b0["from"] != sender {
		t.Fatalf("blob mismatch: %v", b0)
	}

	// Ack removes it.
	resp, out = e.post(t, "/rendezvous/signal/"+rcpt+"/ack", e.ack(domainSignalAck, rcptPriv, rcpt, []string{id}))
	if resp.StatusCode != 200 || out["deleted"].(float64) != 1 {
		t.Fatalf("ack failed: %d %v", resp.StatusCode, out)
	}
	// Poll again => empty.
	_, out = e.post(t, "/rendezvous/signal/"+rcpt+"/poll", e.poll(domainSignalPoll, rcptPriv, rcpt, 0))
	if blobs, _ := out["blobs"].([]any); len(blobs) != 0 {
		t.Fatalf("expected empty after ack, got %v", out["blobs"])
	}
}

func TestPollRequiresRecipientKey(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, senderPriv, sender := genKey(t)
	_, _, rcpt := genKey(t)
	_, attackerPriv, _ := genKey(t)

	payload := b64.EncodeToString([]byte("secret"))
	e.post(t, "/rendezvous/signal/"+rcpt, e.deposit(domainSignalDeposit, senderPriv, sender, rcpt, payload, 0))

	// Attacker tries to poll recipient's mailbox by claiming rcpt but signing with
	// their own key.
	req := pollRequest{Key: rcpt, Nonce: freshNonce(), Timestamp: e.now().Unix()}
	req.Sig = b64.EncodeToString(ed25519.Sign(attackerPriv, pollSigningMessage(domainSignalPoll, &req)))
	resp, _ := e.post(t, "/rendezvous/signal/"+rcpt+"/poll", req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("attacker poll must be 401, got %d", resp.StatusCode)
	}
}

func TestDepositRecipientMismatchRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, senderPriv, sender := genKey(t)
	_, _, rcptA := genKey(t)
	_, _, rcptB := genKey(t)
	// Sign for rcptA but POST to rcptB's path.
	req := e.deposit(domainSignalDeposit, senderPriv, sender, rcptA, b64.EncodeToString([]byte("x")), 0)
	resp, _ := e.post(t, "/rendezvous/signal/"+rcptB, req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("recipient mismatch must be 400, got %d", resp.StatusCode)
	}
}

func TestSignalDomainSeparation(t *testing.T) {
	// A signature minted for a mailbox deposit must NOT verify as a signal deposit.
	e := newTestEnv(t, Config{})
	_, senderPriv, sender := genKey(t)
	_, _, rcpt := genKey(t)
	req := e.deposit(domainMailboxDeposit, senderPriv, sender, rcpt, b64.EncodeToString([]byte("x")), 0)
	// Submit the mailbox-signed request to the SIGNAL endpoint.
	resp, _ := e.post(t, "/rendezvous/signal/"+rcpt, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-domain sig reuse must be 401, got %d", resp.StatusCode)
	}
}

func TestLongPollWakesOnDeposit(t *testing.T) {
	e := newTestEnv(t, Config{MaxPollWait: 3 * time.Second})
	_, senderPriv, sender := genKey(t)
	_, rcptPriv, rcpt := genKey(t)

	done := make(chan int, 1)
	go func() {
		resp, out := e.post(t, "/rendezvous/signal/"+rcpt+"/poll", e.poll(domainSignalPoll, rcptPriv, rcpt, 2))
		if resp.StatusCode != 200 {
			done <- -1
			return
		}
		blobs, _ := out["blobs"].([]any)
		done <- len(blobs)
	}()

	// Give the long-poll a moment to register, then deposit.
	time.Sleep(100 * time.Millisecond)
	payload := b64.EncodeToString([]byte("late-offer"))
	resp, _ := e.post(t, "/rendezvous/signal/"+rcpt, e.deposit(domainSignalDeposit, senderPriv, sender, rcpt, payload, 0))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deposit failed: %d", resp.StatusCode)
	}

	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("long-poll expected 1 blob, got %d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll did not wake on deposit")
	}
}

// ── MAILBOX caps / quota / TTL ───────────────────────────────────────────────

func TestMailboxBlobTooLarge(t *testing.T) {
	e := newTestEnv(t, Config{MailboxCaps: queueCaps{MaxBlobBytes: 32}})
	_, senderPriv, sender := genKey(t)
	_, _, rcpt := genKey(t)
	big := b64.EncodeToString(bytes.Repeat([]byte("A"), 64)) // 64 raw bytes > 32 cap
	resp, _ := e.post(t, "/rendezvous/mailbox/"+rcpt, e.deposit(domainMailboxDeposit, senderPriv, sender, rcpt, big, 0))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestMailboxPerKeyBlobQuota(t *testing.T) {
	e := newTestEnv(t, Config{MailboxCaps: queueCaps{MaxPerKeyBlobs: 2}})
	_, senderPriv, sender := genKey(t)
	_, _, rcpt := genKey(t)
	pay := b64.EncodeToString([]byte("m"))
	for i := 0; i < 2; i++ {
		resp, _ := e.post(t, "/rendezvous/mailbox/"+rcpt, e.deposit(domainMailboxDeposit, senderPriv, sender, rcpt, pay, 0))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("deposit %d failed: %d", i, resp.StatusCode)
		}
	}
	resp, _ := e.post(t, "/rendezvous/mailbox/"+rcpt, e.deposit(domainMailboxDeposit, senderPriv, sender, rcpt, pay, 0))
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("expected 507 quota, got %d", resp.StatusCode)
	}
}

func TestMailboxTTLClampAndExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	svc := New(Config{now: clock.now, MailboxCaps: queueCaps{MaxTTL: time.Hour, DefaultTTL: time.Hour}})
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()
	e := &testEnv{svc: svc, ts: ts, now: clock.now}

	_, senderPriv, sender := genKey(t)
	_, rcptPriv, rcpt := genKey(t)
	pay := b64.EncodeToString([]byte("m"))
	// Request 100h; must be clamped to the 1h MaxTTL.
	resp, out := e.post(t, "/rendezvous/mailbox/"+rcpt, e.deposit(domainMailboxDeposit, senderPriv, sender, rcpt, pay, 360000))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deposit failed: %d", resp.StatusCode)
	}
	exp := int64(out["expires_at"].(float64))
	if exp != clock.now().Add(time.Hour).Unix() {
		t.Fatalf("ttl not clamped to 1h: exp=%d now=%d", exp, clock.now().Unix())
	}
	clock.advance(2 * time.Hour)
	_, out = e.post(t, "/rendezvous/mailbox/"+rcpt+"/poll", e.poll(domainMailboxPoll, rcptPriv, rcpt, 0))
	if blobs, _ := out["blobs"].([]any); len(blobs) != 0 {
		t.Fatalf("expected expired mailbox empty, got %v", out["blobs"])
	}
}

// ── ICE ──────────────────────────────────────────────────────────────────────

func TestICESTUNOnly(t *testing.T) {
	e := newTestEnv(t, Config{})
	resp, out := e.get(t, "/rendezvous/ice")
	if resp.StatusCode != 200 {
		t.Fatalf("ice status=%d", resp.StatusCode)
	}
	servers, _ := out["ice_servers"].([]any)
	if len(servers) == 0 {
		t.Fatalf("expected default STUN, got %v", out)
	}
	s0 := servers[0].(map[string]any)
	if _, hasCred := s0["credential"]; hasCred {
		t.Fatalf("STUN entry must not carry a credential: %v", s0)
	}
}

func TestICEEphemeralTURNCredential(t *testing.T) {
	e := newTestEnv(t, Config{ICE: ICEConfig{
		DisablePublicSTUN: true,
		TURNURLs:          []string{"turn:turn.example.org:3478?transport=udp"},
		TURNSecret:        "s3cr3t",
		TURNCredentialTTL: time.Hour,
	}})
	resp, out := e.get(t, "/rendezvous/ice?key=abc")
	if resp.StatusCode != 200 {
		t.Fatalf("ice status=%d", resp.StatusCode)
	}
	servers, _ := out["ice_servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("expected 1 TURN server, got %v", out)
	}
	s0 := servers[0].(map[string]any)
	user, _ := s0["username"].(string)
	cred, _ := s0["credential"].(string)
	if user == "" || cred == "" {
		t.Fatalf("TURN must carry ephemeral creds: %v", s0)
	}
	// username is "<expiry>:<hint>"; the secret never appears.
	if !strings.Contains(user, ":abc") {
		t.Fatalf("username hint missing: %q", user)
	}
	if strings.Contains(cred, "s3cr3t") {
		t.Fatalf("credential must not leak the secret")
	}
}

// ── malformed / oversize ─────────────────────────────────────────────────────

func TestMalformedJSONRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	resp, err := http.Post(e.ts.URL+"/rendezvous/announce", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestUnknownFieldsRejected(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, _, key := genKey(t)
	body := `{"key":"` + key + `","ts":1,"nonce":"x","sig":"y","evil":true}`
	resp, err := http.Post(e.ts.URL+"/rendezvous/announce", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", resp.StatusCode)
	}
}

func TestHealth(t *testing.T) {
	e := newTestEnv(t, Config{})
	resp, out := e.get(t, "/rendezvous/healthz")
	if resp.StatusCode != 200 || out["role"] != "rendezvous" {
		t.Fatalf("health bad: %d %v", resp.StatusCode, out)
	}
}

func TestStatsCounters(t *testing.T) {
	e := newTestEnv(t, Config{})
	_, priv, key := genKey(t)
	e.post(t, "/rendezvous/announce", e.announce(priv, key, []string{"wss://x"}, "", 300))
	e.get(t, "/rendezvous/resolve/"+key)
	st := e.svc.Stats()
	if st.Announces != 1 || st.Resolves != 1 || st.LivePresence != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}
