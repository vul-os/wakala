#!/usr/bin/env node
// Dev-only smoke test: hits all six routes, fails on any console error/pageerror. Not part of
// the shipped screenshot flow — ad hoc verification only.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(__dirname, '..', 'dist');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff' };
const server = createServer(async (req, res) => {
  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  let filePath = path.join(distDir, urlPath === '/' ? 'index.html' : urlPath);
  if (!existsSync(filePath) || !statSync(filePath).isFile()) filePath = path.join(distDir, 'index.html');
  const body = await readFile(filePath);
  res.writeHead(200, { 'content-type': MIME[path.extname(filePath)] ?? 'application/octet-stream' });
  res.end(body);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const page = await browser.newPage();
let errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

for (const route of ['overview', 'descriptor', 'tariff', 'billing', 'keys', 'conformance']) {
  await page.goto(`${base}/#/${route}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  console.log(`checked #/${route}`);
}

await browser.close();
server.close();
if (errors.length) {
  console.error('ERRORS:', errors);
  process.exit(1);
} else {
  console.log('no console errors across all six routes');
}
