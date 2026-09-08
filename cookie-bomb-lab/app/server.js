/**
 * Cookie Bomb lab app.
 *
 * VULNERABLE: tracking / campaign query parameters are persisted as cookies
 * with no size limit. After a malicious link plants oversized cookies, the
 * next request's Cookie header exceeds the HTTP header limit
 * (--max-http-header-size=8192, simulating a reverse-proxy 8KiB cap).
 * The victim then gets 400 / 431 until they clear cookies.
 */
const express = require('express');
const cookieParser = require('cookie-parser');

const PORT = Number(process.env.PORT || 3200);
const HEADER_LIMIT = Number(process.env.HEADER_LIMIT || 8192);

const TRACKING_PARAM = /^(utm_|ref$|affiliate$|track|tid$|fbclid$|gclid$|campaign)/i;

const app = express();
app.use(cookieParser());

function isTrackingKey(key) {
  return TRACKING_PARAM.test(String(key || ''));
}

function cookieEntries(req) {
  return Object.entries(req.cookies || {}).map(([name, value]) => ({
    name,
    length: String(value).length,
    preview: String(value).slice(0, 48),
  }));
}

function cookieHeaderBytes(req) {
  const raw = req.headers.cookie || '';
  return Buffer.byteLength(raw);
}

// Persist every tracking query parameter as a cookie — no max-length check.
app.use((req, res, next) => {
  for (const [key, raw] of Object.entries(req.query || {})) {
    if (!isTrackingKey(key)) continue;
    const value = Array.isArray(raw) ? raw.join('') : String(raw);
    res.cookie(key, value, {
      path: '/',
      httpOnly: false,
      sameSite: 'lax',
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
    console.log(`[cookie-bomb] stored cookie ${key} (${Buffer.byteLength(value)} bytes)`);
  }
  next();
});

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: Georgia, serif; max-width: 860px; margin: 2rem auto; line-height: 1.5; color: #1a1a1a; }
    code, pre, .mono { font-family: Consolas, ui-monospace, monospace; }
    a { color: #0f4c81; }
    nav a { margin-right: 1rem; }
    .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #ddd; text-align: left; padding: 0.4rem 0.5rem; }
    .bar { height: 10px; background: #fee2e2; margin: 0.5rem 0 1rem; }
    .bar > span { display: block; height: 10px; background: #b91c1c; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/shop">Shop</a>
    <a href="/account">Account</a>
    <a href="/clear">Clear cookies</a>
  </nav>
  ${body}
</body>
</html>`;
}

function statusBlock(req) {
  const entries = cookieEntries(req);
  const used = cookieHeaderBytes(req);
  const pct = Math.min(100, Math.round((used / HEADER_LIMIT) * 100));
  const rows = entries.length
    ? entries
        .map(
          (c) =>
            `<tr><td><code>${c.name}</code></td><td>${c.length} bytes</td><td class="mono">${c.preview}${c.length > 48 ? '…' : ''}</td></tr>`
        )
        .join('')
    : '<tr><td colspan="3"><em>No cookies yet.</em></td></tr>';
  return `
    <p class="${used > HEADER_LIMIT * 0.6 ? 'warn' : 'ok'}">
      Cookie header: <strong>${used}</strong> / ${HEADER_LIMIT} bytes (${pct}%).
      If this exceeds the HTTP header limit, every later request fails with
      <code>400</code> / <code>431</code> until cookies are cleared.
    </p>
    <div class="bar"><span style="width:${pct}%"></span></div>
    <table>
      <thead><tr><th>Cookie</th><th>Size</th><th>Preview</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

app.get('/', (req, res) => {
  res.send(
    layout(
      'ShopHome — Cookie Bomb Lab',
      `
      <h1>ShopHome</h1>
      <p>Marketing “helps” us remember campaigns by storing <code>utm_*</code>,
      <code>ref</code>, <code>affiliate</code>, <code>fbclid</code> and similar
      query parameters as cookies — <strong>with no size limit</strong>.</p>
      ${statusBlock(req)}
      <h2>Harmless tracking example</h2>
      <p><a href="/?utm_source=newsletter&utm_campaign=spring">Arrive from a newsletter</a></p>
      <h2>Lab</h2>
      <ul>
        <li>Vulnerable app: <code>http://localhost:3200</code></li>
        <li>WAF gate: <code>http://localhost:8280</code></li>
        <li>Malicious link: <code>http://localhost:9299/cookie-bomb.html</code></li>
      </ul>`
    )
  );
});

app.get('/shop', (req, res) => {
  res.send(
    layout(
      'Shop',
      `<h1>Shop</h1><p>This page also needs a valid request. After a cookie bomb it becomes unreachable.</p>${statusBlock(req)}`
    )
  );
});

app.get('/account', (req, res) => {
  res.send(
    layout(
      'Account',
      `<h1>Account</h1><p>Session still looks fine — until the Cookie header is too large for the parser.</p>${statusBlock(req)}`
    )
  );
});

app.get('/clear', (req, res) => {
  const names = new Set([
    ...Object.keys(req.cookies || {}),
    'utm_source',
    'utm_medium',
    'utm_campaign',
    'utm_content',
    'utm_term',
    'ref',
    'affiliate',
    'track',
    'tid',
    'fbclid',
    'gclid',
  ]);
  for (const name of names) {
    res.clearCookie(name, { path: '/' });
  }
  res.send(
    layout(
      'Cookies cleared',
      `<h1>Cookies cleared</h1><p>Lab reset. <a href="/">Back home</a>.</p>`
    )
  );
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, lab: 'cookie-bomb', headerLimit: HEADER_LIMIT });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[cookie-bomb] ShopHome on ${PORT} (max HTTP header ${HEADER_LIMIT} bytes)`);
  console.log('[cookie-bomb] tracking query params are stored as unbounded cookies');
});
