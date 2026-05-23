<div align="center">

# Vulos Relay

**Outbound mail deliverability + Vulos-to-Vulos peering — one delivery path**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vul-os/vulos-relay/pulls)

*Vulos — rooted in **vula**, the Zulu and Xhosa word for **open**.*

</div>

---

## What is Vulos Relay?

Vulos Relay is the **outbound delivery path** for Vulos mail. It is open source
(MIT, Go) and holds two halves of the same job in one repo:

1. **The relay** — a smarthost backed by a shared pool of **warmed IPs**. Most
   senders, especially the low-volume long tail, use it as their permanent
   outbound path: a dedicated IP needs thousands of messages a day to stay warm,
   so a managed shared pool gives *better* deliverability than a cold dedicated
   IP ever would. Dedicated-IP-direct is a premium option for high-volume senders.
2. **Peering** — when the sender and recipient are *both* Vulos, the message is
   handed off over the Vulos fabric/bucket transport instead of public SMTP.
   That path is encrypted and bypasses DNS, blocklists, and spam filters
   entirely. Anything bound for a non-Vulos recipient falls back to standard SMTP.

Both halves are "how a message leaves the building," which is why they share a
repo. The peering wire format is documented as a **versioned spec** (see
[`spec/`](spec/)) so that other operators can run Vulos-compatible nodes and
peer — open federation is a goal, not an accident.

> *"Vula" — open the door. Vulos Relay is how the mail walks through it.*

---

## Where it fits

| Repo | Role |
|---|---|
| **vulos-relay** (this repo) | Outbound deliverability + Vulos-to-Vulos peering |
| [vulos-mail](https://github.com/vul-os/vulos-mail) | The mail **server** — SMTP/IMAP/JMAP + storage (a [Mox](https://github.com/mjl-/mox) fork) |
| [Vulos](https://github.com/vul-os/vulos) | The sovereign, self-hostable OS the whole project is built around |

`vulos-mail` runs the mailbox; `vulos-relay` gets the mail *out* and keeps the
sending reputation healthy. The closed `vulos-cloud` control plane operates this
relay as a multi-tenant, warmed-IP service — but the relay is fully
**self-hostable standalone**, with no dependency on Vulos's cloud.

---

## Design principles

- **Pluggable backends.** "Where do I get mail to send?" (the queue) and "what is
  my sending-reputation policy?" are **interfaces**. Vulos plugs in a
  bucket-backed queue and its own reputation policy; you plug in yours. The OSS
  repo is never hardwired to Vulos's bucket layout.
- **Security from cryptography, not secrecy.** The peering protocol is a published,
  versioned spec designed to be cryptographically sound and safe to interoperate
  against — not a closed handshake.
- **Reuse the giants.** Outbound SMTP leans on the battle-tested
  [Mox](https://github.com/mjl-/mox) `smtpclient` rather than a from-scratch MTA.

---

## Features

| | |
|---|---|
| **Shared warm pool** | Managed pool of warmed IPs — the long tail's permanent outbound path |
| **IP warm-up ramp** | Per-IP daily-cap ramp (50 → 200 → 500 → 1k → 2.5k/day) |
| **Reputation telemetry** | Google Postmaster Tools + Microsoft SNDS auto-registration |
| **Blocklist monitoring** | Spamhaus / SORBS / Barracuda / SenderScore polling + auto-delisting |
| **DKIM rotation** | Scheduled key rotation |
| **Outbound scanning** | Rspamd content scan before send |
| **Reputation scoring** | Per-account sending-reputation scoring + instant suspension on abuse |
| **Pool segmentation** | Pools split by trust / age |
| **Peering** | Encrypted Vulos-to-Vulos handoff over the fabric, SMTP fallback otherwise |
| **Open federation** | Versioned peering wire spec so others can run compatible nodes |

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

Made with care · Powered by open source · *Vula — open*

</div>
