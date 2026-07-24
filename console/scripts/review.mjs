// Scratch review capture — all pages, desktop + mobile, into the scratch dir.
// Not committed output; for design review only.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const consoleRoot = path.resolve(__dirname, '..');
const distDir = path.join(consoleRoot, 'dist');
const outDir = process.argv[2] || '/tmp/review';

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.json': 'application/json', '.png': 'image/png' };
const server = createServer(async (req, res) => {
  let rel = decodeURIComponent(req.url.split('?')[0]);
  if (rel === '/' || !existsSync(path.join(distDir, rel))) rel = '/index.html';
  try {
    const buf = await readFile(path.join(distDir, rel));
    res.setHeader('Content-Type', MIME[path.extname(rel)] || 'application/octet-stream');
    res.end(buf);
  } catch { res.statusCode = 404; res.end('nf'); }
});
await new Promise((r) => server.listen(0, r));
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;
const browser = await chromium.launch();

const PAGES = ['overview', 'descriptor', 'tariff', 'billing', 'keys', 'conformance'];

async function shoot(route, { width, height, file, scheme = 'dark', drawer = false }) {
  const ctx = await browser.newContext({ viewport: { width, height }, colorScheme: scheme, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.goto(`${base}/#/${route}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(700);
  if (drawer) { await page.click('.hamburger'); await page.waitForTimeout(400); }
  await page.screenshot({ path: path.join(outDir, file), fullPage: !drawer });
  console.log('wrote', file);
  await ctx.close();
}

try {
  for (const p of PAGES) await shoot(p, { width: 1440, height: 900, file: `d-${p}.png` });
  // mobile: overview full page + drawer open
  await shoot('overview', { width: 390, height: 844, file: 'm-overview.png' });
  await shoot('billing', { width: 390, height: 844, file: 'm-billing.png' });
  await shoot('overview', { width: 390, height: 844, file: 'm-drawer.png', drawer: true });
} finally {
  await browser.close();
  server.close();
}
