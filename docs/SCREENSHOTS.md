# Screenshots — @vulos/relay-client

Because `@vulos/relay-client` is a headless JS SDK (a library with no app UI),
the visual documentation uses an **interactive demo harness** (`demo/index.html`)
that exercises the SDK in a real browser:

- **Endpoint failover panel** — live status of the cloud ↔ LAN probe cycle,
  current selected endpoint, and a manual "force re-probe" button.
- **Fabric/presence panel** — a simulated two-peer fabric session using
  in-process stub peers (no real backend required); displays the full roster
  roster, peer connection states, and a broadcast message log.
- **Architecture diagram** — an embedded SVG sequence diagram of the signaling
  + relay-fallback flow, rendered to a standalone PNG (`docs/screenshots/architecture.png`).

## Captured screenshots

| File | What it shows |
|------|---------------|
| `docs/screenshots/hero.png` | Demo harness overview (endpoint + presence panels) |
| `docs/screenshots/architecture.png` | Architecture / sequence diagram |

## Prerequisites

```bash
cd scripts
npm ci
```

Playwright downloads a headless Chromium binary on first install (~170 MB).

## Regenerate

From the repo root:

```bash
npm run screenshots
```

This runs `scripts/screenshots.mjs`, which:

1. Launches a local static file server serving `demo/index.html`.
2. Opens a headless Chromium page and waits for the demo to initialise.
3. Captures `hero.png` (full-page, 1280 × 900).
4. Captures `architecture.png` (the architecture diagram section).
5. Writes both PNGs to `docs/screenshots/`.

## Demo source

`demo/index.html` is self-contained (no build step). It imports the SDK's
pre-built ESM bundle directly from `client/dist-lib/` via a relative path,
then uses in-process stub peers (via `BroadcastChannel` simulation) to drive
the fabric and presence layers without a real backend.

The demo intentionally does **not** fake a screenshot of a non-existent app UI;
everything shown is real SDK behaviour running in the browser.
