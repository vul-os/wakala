#!/usr/bin/env node
// Builds (if needed) aren't run here — this script assumes `pnpm build` already produced
// `dist/`. It serves that build statically, loads the console in mock mode (the build's
// default, VITE_MOCK=1), and captures the four reference screenshots into ../docs/img.
//
// Usage: node scripts/screenshot.mjs   (or `pnpm screenshot`, after `pnpm build`)

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const consoleRoot = path.resolve(__dirname, '..');
const distDir = path.join(consoleRoot, 'dist');
const outDir = path.resolve(consoleRoot, '..', 'docs', 'img');

if (!existsSync(distDir)) {
  console.error('dist/ not found — run `pnpm build` first.');
  process.exit(1);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.json': 'application/json',
  '.png': 'image/png',
};

const server = createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent(req.url.split('?')[0]);
    let filePath = path.join(distDir, urlPath === '/' ? 'index.html' : urlPath);
    if (!filePath.startsWith(distDir)) throw new Error('bad path');
    if (!existsSync(filePath) || !(await (await import('node:fs/promises')).stat(filePath)).isFile()) {
      filePath = path.join(distDir, 'index.html'); // SPA fallback (hash routing anyway)
    }
    const body = await readFile(filePath);
    res.writeHead(200, { 'content-type': MIME[path.extname(filePath)] ?? 'application/octet-stream' });
    res.end(body);
  } catch (e) {
    res.writeHead(500);
    res.end(String(e));
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const { port } = server.address();
const base = `http://127.0.0.1:${port}`;
console.log(`serving dist/ at ${base}`);

const browser = await chromium.launch();

async function shoot({ route, colorScheme, file, waitForSelector }) {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    colorScheme,
    deviceScaleFactor: 2,
  });
  const page = await context.newPage();
  await page.goto(`${base}/#/${route}`, { waitUntil: 'networkidle' });
  if (waitForSelector) await page.waitForSelector(waitForSelector, { timeout: 10_000 });
  // let the mock client's artificial latency + font swap settle
  await page.waitForTimeout(700);
  const outPath = path.join(outDir, file);
  // Full-page (not just the 1440x900 fold) so the audit-caveat / receipts ledger and the
  // rest of each view's content is actually visible in the reference screenshot, not cut off.
  await page.screenshot({ path: outPath, fullPage: true });
  console.log(`wrote ${path.relative(consoleRoot, outPath)}`);
  await context.close();
}

try {
  await shoot({
    route: 'overview',
    colorScheme: 'dark',
    file: 'console-dark.png',
    waitForSelector: 'text=Coordinator posture',
  });
  await shoot({
    route: 'overview',
    colorScheme: 'light',
    file: 'console-light.png',
    waitForSelector: 'text=Coordinator posture',
  });
  await shoot({
    route: 'billing',
    colorScheme: 'dark',
    file: 'console-billing-dark.png',
    waitForSelector: 'text=Prepaid ledger',
  });
  await shoot({
    route: 'billing',
    colorScheme: 'light',
    file: 'console-billing-light.png',
    waitForSelector: 'text=Prepaid ledger',
  });
} finally {
  await browser.close();
  server.close();
}
