#!/usr/bin/env node
/**
 * screenshots.mjs — @vulos/relay-client screenshotter
 *
 * Serves demo/index.html on a local static file server, then uses Playwright
 * (headless Chromium) to capture:
 *
 *   docs/screenshots/hero.png         — full demo harness (endpoint + presence panels)
 *   docs/screenshots/architecture.png — architecture / sequence diagram section
 *
 * Usage (from repo root):
 *   npm run screenshots
 *
 * Or directly:
 *   cd scripts && npm ci && node screenshots.mjs
 *
 * Prerequisites: Node.js 20+, `npm ci` in scripts/ (installs Playwright +
 * downloads a headless Chromium binary ~170 MB on first run).
 */

import { chromium } from '@playwright/test'
import { createServer } from 'node:http'
import { readFileSync, mkdirSync } from 'node:fs'
import { resolve, dirname, extname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..')
const DEMO_DIR = resolve(ROOT, 'demo')
const DIST_DIR = resolve(ROOT, 'client', 'dist-lib')
const OUT_DIR  = resolve(ROOT, 'docs', 'screenshots')

// ── Ensure output directory exists ──────────────────────────────────────────

mkdirSync(OUT_DIR, { recursive: true })

// ── MIME map ─────────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.cjs':  'application/javascript',
  '.mjs':  'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
}

// ── Static file server ───────────────────────────────────────────────────────
// Serves:
//   /             → demo/index.html
//   /demo/*       → demo/
//   /dist-lib/*   → client/dist-lib/   (SDK bundles, for the demo to import)

function serveFile(filePath, res) {
  try {
    const body = readFileSync(filePath)
    const mime = MIME[extname(filePath)] || 'application/octet-stream'
    res.writeHead(200, { 'Content-Type': mime })
    res.end(body)
  } catch {
    res.writeHead(404)
    res.end('Not found: ' + filePath)
  }
}

const server = createServer((req, res) => {
  // CORS — not needed for a local demo, but harmless
  res.setHeader('Access-Control-Allow-Origin', '*')

  const url = new URL(req.url, 'http://localhost')
  const path = url.pathname

  if (path === '/' || path === '/index.html') {
    serveFile(resolve(DEMO_DIR, 'index.html'), res)
  } else if (path.startsWith('/dist-lib/')) {
    serveFile(resolve(DIST_DIR, path.slice('/dist-lib/'.length)), res)
  } else if (path.startsWith('/demo/')) {
    serveFile(resolve(DEMO_DIR, path.slice('/demo/'.length)), res)
  } else {
    res.writeHead(404); res.end('Not found')
  }
})

await new Promise((resolve, reject) =>
  server.listen(0, '127.0.0.1', (err) => err ? reject(err) : resolve())
)

const port = server.address().port
const baseUrl = `http://127.0.0.1:${port}`
console.log(`[screenshots] Static server → ${baseUrl}`)

// ── Playwright ───────────────────────────────────────────────────────────────

const browser = await chromium.launch()
const page = await browser.newPage({
  viewport: { width: 1280, height: 900 },
})

page.on('console', msg => {
  if (msg.type() === 'error') console.warn('[page error]', msg.text())
})

console.log('[screenshots] Navigating to demo…')
await page.goto(baseUrl, { waitUntil: 'networkidle' })

// Wait for the demo harness to signal it is initialised.
// The demo sets #demo-ready display:block after 800 ms.
await page.waitForSelector('#demo-ready', { state: 'visible', timeout: 10_000 })
  .catch(() => console.warn('[screenshots] demo-ready marker not found; capturing anyway'))

// Give the probe animation a moment to settle
await page.waitForTimeout(600)

// ── Capture 1: hero (full page) ───────────────────────────────────────────

const heroPath = resolve(OUT_DIR, 'hero.png')
await page.screenshot({ path: heroPath, fullPage: true })
console.log('[screenshots] Saved →', heroPath)

// ── Capture 2: architecture diagram section ───────────────────────────────

const archEl = await page.$('#panel-arch')
if (archEl) {
  const archPath = resolve(OUT_DIR, 'architecture.png')
  await archEl.screenshot({ path: archPath })
  console.log('[screenshots] Saved →', archPath)
} else {
  console.warn('[screenshots] #panel-arch not found; skipping architecture capture')
}

// ── Cleanup ───────────────────────────────────────────────────────────────

await browser.close()
server.close()

console.log('[screenshots] Done. Outputs in docs/screenshots/')
