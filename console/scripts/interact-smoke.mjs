#!/usr/bin/env node
// Ad hoc interaction smoke test — exercises the mutating mock flows (rotate keys, sign
// descriptor incl. downgrade warning, publish tariff, top up, run billing) headlessly.
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
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

// Keys: rotate
await page.goto(`${base}/#/keys`, { waitUntil: 'networkidle' });
await page.getByRole('button', { name: 'Rotate key →' }).click();
await page.getByRole('button', { name: 'Confirm rotation' }).click();
await page.waitForTimeout(400);
await page.waitForSelector('text=Rotated from');
console.log('keys: rotate ok');

// Descriptor: trigger a downgrade warning (blind-routing/declared -> terminating/declared)
await page.goto(`${base}/#/descriptor`, { waitUntil: 'networkidle' });
await page.selectOption('#vclass', 'terminating');
await page.waitForSelector('text=This is a visibility downgrade.');
const disabledBefore = await page.getByRole('button', { name: 'Sign & publish' }).isDisabled();
if (!disabledBefore) throw new Error('expected publish disabled before confirming downgrade');
await page.getByLabel('I am intentionally disclosing this downgrade').check();
await page.getByRole('button', { name: 'Sign & publish' }).click();
await page.waitForSelector('text=Published — re-signed');
console.log('descriptor: downgrade-confirm publish ok');

// Tariff: apply recommended + publish
await page.goto(`${base}/#/tariff`, { waitUntil: 'networkidle' });
await page.getByRole('button', { name: 'Apply to draft below →' }).click();
await page.getByRole('button', { name: 'Sign & publish tariff' }).click();
await page.waitForSelector('text=Published — attached');
console.log('tariff: publish ok');

// Billing: top up + run billing period
await page.goto(`${base}/#/billing`, { waitUntil: 'networkidle' });
await page.getByRole('button', { name: 'Top up →' }).click();
await page.getByRole('button', { name: 'Confirm top-up' }).click();
await page.waitForTimeout(400);
await page.getByRole('button', { name: /Run billing period/ }).click();
await page.waitForTimeout(400);
console.log('billing: top-up + run billing ok');

await browser.close();
server.close();
if (errors.length) {
  console.error('ERRORS:', errors);
  process.exit(1);
}
console.log('interaction smoke test passed, no console errors');
