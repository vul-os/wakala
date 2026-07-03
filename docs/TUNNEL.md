# Vulos Sovereign Reverse Tunnel

A self-hosted reverse tunnel that lets a loopback-bound Vulos box publish itself on
the public internet **without opening any inbound ports, without a static IP, and
without any third-party relay** (it replaces external `frp`).

The box runs an **agent** that dials a **single outbound `wss://` connection** to a
Vulos **relay server** you control. The relay serves a public URL and reverse-
proxies inbound requests back down that one connection to the box's local port.

```
   public client                    relay server (public)                box (loopback only)
        │  https://box1.relay.example.com     │                                 │
        ├────────────────────────────────────►│                                 │
        │                                      │  yamux stream (1 per request)   │
        │                                      ├────────────────────────────────►│  agent
        │                                      │   over ONE outbound wss control │   │ dials localhost:8080
        │                                      │   connection the AGENT opened   │   ▼
        │◄─────────── response ────────────────┤◄────────────────────────────────┤  local app
```

Only **outbound 443** is required from the box. The box binds nothing inbound.

---

## Transport & design

- **One outbound connection.** The agent opens a single `wss://` WebSocket to the
  relay's control endpoint (`/_vulos-relay/control`). WebSocket is edge/CDN/TLS-
  termination friendly and only needs outbound 443.
- **Multiplexing with yamux.** After a JSON handshake, both sides hand that
  WebSocket's `net.Conn` to [`hashicorp/yamux`](https://github.com/hashicorp/yamux).
  The **relay is the yamux client** (opens one stream per inbound public request);
  the **agent is the yamux server** (accepts streams, proxies each to its one local
  target). Each stream carries a plain HTTP/1.1 request/response — no extra framing —
  which is also what makes **WebSocket-upgrade passthrough** transparent.
- **Routing.**
  - **Subdomain mode (primary):** `https://<name>.<relay-domain>` — needs a wildcard
    DNS record `*.relay.example.com`.
  - **Path mode (fallback):** `https://<relay-domain>/t/<name>/…` — enable with
    `-path-mode` when you can't provision wildcard DNS.
- **Reconnect.** The agent maintains the tunnel with exponential backoff + full
  jitter and reconnects automatically after any drop.

## Security model (fails closed — this is internet-facing)

- **Agent auth:** a per-agent **bearer token** (`Authorization: Bearer …`, also
  echoed in the register frame; they must agree). Validated with **constant-time**
  comparison. Unauthenticated control connections are rejected before/after upgrade.
- **Name binding:** a token may serve **only the name(s) it is granted**. Names
  cannot be hijacked — a live name is held by exactly one session (first-come);
  a second claimant is rejected, not swapped in.
- **SSRF guard:** the agent forwards **only** to its one configured `localhost:PORT`
  target — never to a host named by the relay or the request. Non-loopback targets
  (private IPs, `169.254.169.254`, arbitrary hosts, `0.0.0.0`) are refused at
  startup and re-checked per stream.
- **Bounds:** max concurrent agents, max concurrent streams/agent, request header
  size cap, request body size cap, control-message size cap, idle timeout, and
  keepalive-based dead-peer detection. Memory is bounded.
- **Header hygiene:** hop-by-hop headers are stripped both ways; `X-Forwarded-For`,
  `X-Forwarded-Host`, `X-Forwarded-Proto` are set from the real client (the agent's
  input is never trusted to name itself). Internal errors are never leaked to
  clients (generic `502`/`403`/etc.).
- **TLS everywhere:** run the relay behind an edge/CDN that terminates TLS, or give
  it `-cert`/`-key` to terminate itself.

## Honest limitations

- **HTTP(S)/WS only.** This tunnels HTTP and WebSocket. It is not a raw TCP/UDP
  tunnel (no SSH/arbitrary-TCP mode like `frp`'s TCP proxy). That covers Vulos web
  surfaces; non-HTTP protocols are out of scope for now.
- **Static token store.** The built-in store is a JSON grants file / env var. It is
  the seam for a signed-token or DB-backed store (`server.TokenStore` interface) but
  those aren't implemented yet.
- **No multi-relay HA / sticky sessions.** A name is served by whichever single
  relay instance the agent connected to. Horizontal scaling of the relay tier needs
  a shared session directory (future work); today, run one relay per region/cell.
- **Dead-peer detection latency.** A hard-killed agent's name frees on the next
  yamux keepalive miss (~10s), not instantly. A clean `Stop()` frees it at once.
- **No per-request auth on the public side.** The relay exposes whatever the local
  app exposes; auth is the app's job (same as `frp`). The relay only authenticates
  *agents*, not *public visitors*.

---

## Running the relay server (`vulos-relayd`)

```
go build -o vulos-relayd ./cmd/vulos-relayd

# Behind a TLS-terminating edge/CDN (recommended), plain HTTP on a private port:
VULOS_RELAY_TOKENS='[{"token":"SECRET1","names":["box1"]}]' \
  ./vulos-relayd -addr :8443 -domain relay.example.com

# Or terminate TLS itself:
./vulos-relayd -addr :443 -domain relay.example.com \
  -cert /etc/tls/fullchain.pem -key /etc/tls/privkey.pem \
  -tokens-file /etc/vulos/relay-tokens.json

# No wildcard DNS? Use path mode:
./vulos-relayd -domain relay.example.com -path-mode -tokens-file grants.json
```

### Flags / env

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `-addr` | | `:8443` | Listen address. |
| `-domain` | `VULOS_RELAY_DOMAIN` | — (required) | Base relay domain. |
| `-tokens-file` | `VULOS_RELAY_TOKENS` (inline JSON) | — (required) | Agent grants. |
| `-path-mode` | | `false` | Also serve `/t/<name>/` fallback. |
| `-cert` / `-key` | | — | Terminate TLS here (omit if behind an edge). |
| `-max-agents` | | `256` | Max concurrent agents. |

**Grants JSON:**
```json
[
  {"token": "SECRET1", "names": ["box1"]},
  {"token": "SECRET2", "names": ["alice", "alice-staging"]}
]
```

### DNS it needs

- **Subdomain mode (primary):** a wildcard `A`/`AAAA` (or `CNAME`) record
  `*.relay.example.com → <relay host>`, plus `relay.example.com` itself. TLS needs a
  wildcard cert (`*.relay.example.com`) — trivial with an ACME edge/CDN.
- **Path mode (fallback):** just `relay.example.com → <relay host>`; no wildcard.

`GET /healthz` returns `ok agents=<n>` for load-balancer health checks.

---

## Running the agent CLI (`vulos-relay-agent`)

```
go build -o vulos-relay-agent ./cmd/vulos-relay-agent

vulos-relay-agent \
  -server wss://relay.example.com \
  -token  SECRET1 \
  -name   box1 \
  -local  127.0.0.1:8080
```

`-local` must be a loopback address. The agent binds nothing inbound.

---

## Embedding the agent (library API)

The `agent` package mirrors wede's `internal/tunnel.Manager` so wede can swap its
frp subprocess for this in-process client. Status vocabulary is identical:
`stopped` / `starting` / `connected` / `error`.

```go
import "github.com/vul-os/vulos-relay/tunnel/agent"

a := agent.New(agent.Options{
    ServerURL: "wss://relay.example.com", // http/https normalized to ws/wss
    Token:     "SECRET1",
    Name:      "box1",
    LocalAddr: "127.0.0.1:8080",          // must be loopback (SSRF guard)
})

// Start returns immediately; it dials + registers + maintains async with backoff.
if err := a.Start(ctx); err != nil { /* bad options */ }

url  := a.PublicURL()   // "https://box1.relay.example.com" when connected, else ""
snap := a.Snapshot()    // { Status, PublicURL, Connected, LastError, Log }

a.Stop()                // tears down; frees the name immediately
```

`Snapshot()` never includes the token. `Options` also has `TLSConfig` (pin a CA for
a self-hosted relay) and `InsecureSkipVerify` (testing only).
