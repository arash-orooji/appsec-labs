/**
 * HarborCart — advanced cookie-poisoning lab.
 *
 * The app stores authorization, identity, cart prices, and a "vault"
 * blob in cookies the browser can edit. That is cookie poisoning
 * (Invicti: modify cookies before they return to the app; F5: forged
 * cookies impersonate users). Stages:
 *
 *  1. Cart price trusted from cookie
 *  2. Base64 JSON identity cookie (no signature)
 *  3. HMAC-SHA256 that does not cover `role=`
 *  4. AES-128-CBC vault cookie with no MAC (IV bit-flip)
 *  5. MD5(secret || data) hash-length extension
 *
 * https://www.f5.com/glossary/cookie-poisoning
 * https://www.invicti.com/learn/cookie-poisoning
 */
const express = require('express');
const cookieParser = require('cookie-parser');
const {
  makeAuthz,
  parseAuthz,
  encryptVault,
  decryptVault,
  bitflipVaultAdmin,
  legacySign,
  hashLengthExtend,
  b64urlEncode,
  b64urlDecode,
  LEGACY_SECRET_LEN,
} = require('./crypto');

const PORT = Number(process.env.PORT || 3400);
const COOKIE_OPTS = { httpOnly: false, sameSite: 'lax', path: '/', maxAge: 24 * 3600 * 1000 };

const FLAGS = {
  cart: 'FLAG{cookie-poison-cart-price}',
  identity: 'FLAG{cookie-poison-identity}',
  hmac: 'FLAG{cookie-poison-hmac-gap}',
  cbc: 'FLAG{cookie-poison-cbc-bitflip}',
  hle: 'FLAG{cookie-poison-hash-extend}',
  master: 'FLAG{cookie-poisoning-complete}',
};

const ALICE = {
  user: 'alice',
  uid: 7,
  email: 'alice@harbor.internal',
  card: 'ACCT-000015',
};

const DEFAULT_CART = 'sku=LAMP|price=49.00|qty=1';

function defaultIdentity() {
  return Buffer.from(JSON.stringify({ user: 'guest', uid: 100 })).toString('base64');
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

function issueMissingCookies(req, res) {
  if (!req.cookies.cart) res.cookie('cart', DEFAULT_CART, COOKIE_OPTS);
  if (!req.cookies.identity) res.cookie('identity', defaultIdentity(), COOKIE_OPTS);
  if (!req.cookies.authz) res.cookie('authz', makeAuthz('guest', 'shopper'), COOKIE_OPTS);
  if (!req.cookies.vault) res.cookie('vault', encryptVault(), COOKIE_OPTS);
  if (!req.cookies.legacy) {
    const data = 'user=guest';
    res.cookie('legacy', b64urlEncode(data), COOKIE_OPTS);
    res.cookie('lsig', legacySign(data), COOKIE_OPTS);
  }
}

app.use((req, res, next) => {
  issueMissingCookies(req, res);
  next();
});

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: Georgia, serif; max-width: 880px; margin: 2rem auto; line-height: 1.5; color: #1a1a1a; }
    code, pre, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.9em; }
    a { color: #0f4c81; }
    nav a { margin-right: 0.85rem; }
    h1 { font-size: 1.7rem; }
    .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
    .err { border-left: 4px solid #b91c1c; padding: 0.75rem 1rem; background: #fef2f2; }
    .lab { border-left: 4px solid #6d28d9; padding: 0.75rem 1rem; background: #f5f3ff; }
    table { border-collapse: collapse; width: 100%; margin: 0.8rem 0; }
    th, td { border-bottom: 1px solid #ddd; text-align: left; padding: 0.35rem 0.45rem; vertical-align: top; }
    button, .btn { font: inherit; padding: 0.4rem 0.8rem; background: #0f4c81; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 0.2rem 0.35rem 0.2rem 0; }
    button.alt { background: #6d28d9; }
    footer { margin-top: 2.2rem; font-size: 0.85rem; color: #6b7280; }
    .break { word-break: break-all; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/shop">Shop</a>
    <a href="/checkout">Checkout</a>
    <a href="/account">Account</a>
    <a href="/admin">Admin</a>
    <a href="/vault">Vault</a>
    <a href="/legacy">Legacy</a>
    <a href="/workbench">Workbench</a>
    <a href="/trophy">Trophy</a>
    <a href="/reset">Reset cookies</a>
  </nav>
  ${body}
  <footer>HarborCart lab — cookie poisoning. WAF gate: <a href="http://localhost:8480">:8480</a></footer>
</body>
</html>`;
}

function cookieTable(req) {
  const names = ['cart', 'identity', 'authz', 'vault', 'legacy', 'lsig'];
  const rows = names
    .map((n) => {
      const v = req.cookies[n];
      const shown = v == null ? '<em>(not set)</em>' : escapeHtml(String(v).slice(0, 160));
      return `<tr><td><code>${n}</code></td><td class="mono break">${shown}${v && String(v).length > 160 ? '…' : ''}</td></tr>`;
    })
    .join('');
  return `<table><thead><tr><th>Cookie</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function parseCart(raw) {
  const p = {};
  for (const part of String(raw || '').split('|')) {
    const i = part.indexOf('=');
    if (i > 0) p[part.slice(0, i)] = part.slice(i + 1);
  }
  return {
    sku: p.sku || 'LAMP',
    price: Number(p.price),
    qty: Number(p.qty || 1),
  };
}

function parseIdentity(raw) {
  try {
    return JSON.parse(Buffer.from(String(raw || ''), 'base64').toString('utf8'));
  } catch {
    return { user: 'guest', uid: 100 };
  }
}

function parseLegacy(req) {
  try {
    const buf = b64urlDecode(req.cookies.legacy || '');
    const sig = String(req.cookies.lsig || '');
    const ok = Boolean(sig) && sig === legacySign(buf);
    return { data: buf.toString('latin1'), sig, ok };
  } catch {
    return { data: '', sig: '', ok: false };
  }
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, lab: 'cookie-poisoning' });
});

app.get('/', (req, res) => {
  res.send(
    layout(
      'HarborCart — Cookie Poisoning Lab',
      `
      <h1>HarborCart</h1>
      <p>We keep your cart, identity, and even a “secure vault” in cookies so
      checkout is fast. Invicti calls <strong>cookie poisoning</strong> the
      act of <em>changing</em> those cookies before they come back to us.
      F5 notes that forged cookies are enough to impersonate a user.</p>
      <div class="lab">
        <strong>Poisoning, not hijacking.</strong> You already have the cookies
        (this browser). Edit them. Do not steal someone else’s session ID —
        rewrite the fields this app trusts.
      </div>
      ${cookieTable(req)}
      <h2>Five stages</h2>
      <ol>
        <li><a href="/checkout">Cart price</a> — unsigned <code>price=</code></li>
        <li><a href="/account">Identity</a> — Base64 JSON, no MAC</li>
        <li><a href="/admin">HMAC gap</a> — MAC covers <code>user=</code> only</li>
        <li><a href="/vault">CBC bit-flip</a> — AES-128-CBC, no integrity</li>
        <li><a href="/legacy">Hash-length extension</a> — <code>MD5(secret || data)</code></li>
      </ol>
      <p><a class="btn" href="/workbench">Open the poison workbench</a></p>`
    )
  );
});

app.get('/shop', (req, res) => {
  const cart = parseCart(req.cookies.cart);
  res.send(
    layout(
      'Shop — HarborCart',
      `
      <h1>Shop</h1>
      <p>Harbor Desk Lamp — listed at <strong>$49.00</strong>. The amount we
      charge is whatever is in your <code>cart</code> cookie.</p>
      ${cookieTable(req)}
      <p>In cart now: <code>${escapeHtml(cart.sku)}</code> × ${cart.qty} @ $${Number.isFinite(cart.price) ? cart.price.toFixed(2) : '?'}</p>
      <p><a class="btn" href="/checkout">Checkout</a></p>`
    )
  );
});

app.get('/checkout', (req, res) => {
  const cart = parseCart(req.cookies.cart);
  const total = (Number.isFinite(cart.price) ? cart.price : 49) * (cart.qty || 1);
  const poisoned = Number.isFinite(cart.price) && cart.price < 1;
  res.send(
    layout(
      'Checkout — HarborCart',
      `
      <h1>Checkout</h1>
      <p>SKU <code>${escapeHtml(cart.sku)}</code> × ${cart.qty}. Charged from cookie:
      <strong>$${total.toFixed(2)}</strong></p>
      ${poisoned ? `<p class="ok">Price poisoned. Flag: <code>${FLAGS.cart}</code></p>` : `<p class="warn">Pay $49? Or poison <code>cart</code> so <code>price</code> is under $1.</p>`}
      ${cookieTable(req)}`
    )
  );
});

app.get('/account', (req, res) => {
  const ident = parseIdentity(req.cookies.identity);
  const isAlice = String(ident.user).toLowerCase() === 'alice' || Number(ident.uid) === ALICE.uid;
  res.send(
    layout(
      'Account — HarborCart',
      `
      <h1>Account</h1>
      <p>Who you are is the <code>identity</code> cookie (Base64 JSON). No signature.</p>
      ${cookieTable(req)}
      ${
        isAlice
          ? `<p class="ok">Impersonating ${escapeHtml(ALICE.user)} (uid ${ALICE.uid}).
             Email ${escapeHtml(ALICE.email)}. Card ${escapeHtml(ALICE.card)}.<br/>
             Flag: <code>${FLAGS.identity}</code></p>`
          : `<p class="warn">You are <code>${escapeHtml(ident.user)}</code> (uid ${escapeHtml(ident.uid)}).
             Poison identity to Alice (<code>uid</code> 7).</p>`
      }`
    )
  );
});

app.get('/admin', (req, res) => {
  const parsed = parseAuthz(req.cookies.authz);
  const admin = parsed.ok && parsed.role === 'admin';
  res.send(
    layout(
      'Admin — HarborCart',
      `
      <h1>Admin</h1>
      <p><code>authz</code> is HMAC-SHA256, but the MAC is only
      <code>HMAC(user=…)</code>. <code>role=</code> is not covered.</p>
      ${cookieTable(req)}
      ${
        !parsed.ok
          ? `<p class="err">authz rejected (${escapeHtml(parsed.reason || 'invalid')}).</p>`
          : admin
            ? `<p class="ok">role=admin accepted for user ${escapeHtml(parsed.user)}.
               Flag: <code>${FLAGS.hmac}</code></p>`
            : `<p class="warn">Authenticated as ${escapeHtml(parsed.user)} with role
               <code>${escapeHtml(parsed.role)}</code>. Keep the MAC, change the role.</p>`
      }`
    )
  );
});

app.get('/vault', (req, res) => {
  let fields = null;
  let err = '';
  try {
    fields = decryptVault(req.cookies.vault);
  } catch (e) {
    err = e.message;
  }
  const win = fields && fields.admin === '1';
  res.send(
    layout(
      'Vault — HarborCart',
      `
      <h1>Encrypted vault cookie</h1>
      <p>AES-128-CBC, random IV, <strong>no HMAC</strong>. Plaintext is
      <code>uid=101&amp;admin=0</code> (the <code>0</code> sits at offset 14,
      inside the first block — flip it via the IV).</p>
      ${cookieTable(req)}
      ${
        err
          ? `<p class="err">Decrypt failed: ${escapeHtml(err)}</p>`
          : win
            ? `<p class="ok">admin=1 after bit-flip. Flag: <code>${FLAGS.cbc}</code></p>`
            : `<p class="warn">Decrypted: <code>${escapeHtml(JSON.stringify(fields))}</code>. Need admin=1.</p>`
      }`
    )
  );
});

app.get('/legacy', (req, res) => {
  const L = parseLegacy(req);
  const win = L.ok && L.data.includes('user=admin');
  res.send(
    layout(
      'Legacy MAC — HarborCart',
      `
      <h1>Legacy MD5 prefix MAC</h1>
      <p>Old signer: <code>lsig = MD5(pepper || legacy_bytes)</code>. Pepper is
      <strong>${LEGACY_SECRET_LEN} bytes</strong>. MD5 is vulnerable to
      <em>hash-length extension</em>: forge <code>user=guest || glue || user=admin</code>
      without the pepper.</p>
      ${cookieTable(req)}
      <p>MAC valid: <strong>${L.ok ? 'yes' : 'no'}</strong>. Data preview:
      <code class="break">${escapeHtml(JSON.stringify(L.data).slice(0, 180))}</code></p>
      ${
        win
          ? `<p class="ok">Length extension accepted. Flag: <code>${FLAGS.hle}</code></p>`
          : `<p class="warn">Need a valid MAC over data that contains <code>user=admin</code>.</p>`
      }`
    )
  );
});

app.get('/trophy', (req, res) => {
  const cart = parseCart(req.cookies.cart);
  const ident = parseIdentity(req.cookies.identity);
  const authz = parseAuthz(req.cookies.authz);
  let vault = {};
  try {
    vault = decryptVault(req.cookies.vault);
  } catch {
    vault = {};
  }
  const L = parseLegacy(req);
  const wins = {
    cart: Number.isFinite(cart.price) && cart.price < 1,
    identity: String(ident.user).toLowerCase() === 'alice' || Number(ident.uid) === 7,
    hmac: authz.ok && authz.role === 'admin',
    cbc: vault.admin === '1',
    hle: L.ok && L.data.includes('user=admin'),
  };
  const all = Object.values(wins).every(Boolean);
  const lis = Object.entries(wins)
    .map(([k, v]) => `<li>${v ? '✓' : '○'} ${k}</li>`)
    .join('');
  res.send(
    layout(
      'Trophy — HarborCart',
      `
      <h1>Trophy</h1>
      <p>Hold every poisoned cookie in one request.</p>
      <ul>${lis}</ul>
      ${all ? `<p class="ok">Master flag: <code>${FLAGS.master}</code></p>` : '<p class="warn">Finish all five stages, then come back.</p>'}
      ${cookieTable(req)}`
    )
  );
});

app.get('/workbench', (req, res) => {
  res.send(
    layout(
      'Workbench — HarborCart',
      `
      <h1>Poison workbench</h1>
      <p>Same edits as DevTools → Application → Cookies. On the WAF gate these
      writes fail closed (F5-style cookie integrity).</p>
      ${cookieTable(req)}
      <p>
        <button type="button" id="p-cart">1. Poison cart price → $0.01</button>
        <button type="button" id="p-id">2. Impersonate Alice</button>
        <button type="button" id="p-hmac">3. Promote role (keep MAC)</button>
        <button type="button" id="p-cbc">4. Bit-flip vault IV</button>
        <button type="button" id="p-hle" class="alt">5. Hash-length-extend legacy</button>
      </p>
      <p class="lab" id="status">Ready.</p>
      <script>
        function readCookie(name) {
          const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[$()*+./?[\\\\]\\\\^{|}-]/g, '\\\\$&') + '=([^;]*)'));
          return m ? decodeURIComponent(m[1]) : '';
        }
        function writeCookie(name, value) {
          document.cookie = name + '=' + encodeURIComponent(value) + '; path=/';
        }
        function bitflip(token) {
          const parts = token.split('.');
          const iv = parts[0].match(/.{2}/g).map(function (h) { return parseInt(h, 16); });
          iv[14] ^= 1;
          const hex = iv.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
          return hex + '.' + parts[1];
        }
        document.getElementById('p-cart').onclick = function () {
          writeCookie('cart', 'sku=LAMP|price=0.01|qty=1');
          location.href = '/checkout';
        };
        document.getElementById('p-id').onclick = function () {
          writeCookie('identity', btoa(JSON.stringify({ user: 'alice', uid: 7 })));
          location.href = '/account';
        };
        document.getElementById('p-hmac').onclick = function () {
          const cur = readCookie('authz');
          writeCookie('authz', cur.replace(/role=[^|]+/, 'role=admin'));
          location.href = '/admin';
        };
        document.getElementById('p-cbc').onclick = function () {
          writeCookie('vault', bitflip(readCookie('vault')));
          location.href = '/vault';
        };
        document.getElementById('p-hle').onclick = async function () {
          const status = document.getElementById('status');
          status.textContent = 'Computing length extension…';
          const res = await fetch('/lab/tools/hle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              dataB64: readCookie('legacy'),
              sig: readCookie('lsig'),
              extra: 'user=admin',
              secretLen: ${LEGACY_SECRET_LEN}
            })
          });
          const out = await res.json();
          if (!out.ok) { status.textContent = out.error || 'hle failed'; return; }
          writeCookie('legacy', out.dataB64);
          writeCookie('lsig', out.sig);
          location.href = '/legacy';
        };
      </script>`
    )
  );
});

app.post('/lab/tools/hle', (req, res) => {
  try {
    const data = b64urlDecode(req.body.dataB64 || '');
    const sig = String(req.body.sig || '');
    const extra = String(req.body.extra || 'user=admin');
    const secretLen = Number(req.body.secretLen || LEGACY_SECRET_LEN);
    if (!data.length || !/^[0-9a-f]{32}$/i.test(sig)) {
      return res.status(400).json({ ok: false, error: 'need dataB64 + 32-hex sig' });
    }
    const forged = hashLengthExtend(data, sig, extra, secretLen);
    res.json({ ok: true, dataB64: forged.dataB64, sig: forged.sig, glueHex: forged.glueHex });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/lab/tools/bitflip', (req, res) => {
  try {
    res.json({ ok: true, vault: bitflipVaultAdmin(req.body.vault || '') });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get('/reset', (req, res) => {
  for (const name of ['cart', 'identity', 'authz', 'vault', 'legacy', 'lsig']) {
    res.clearCookie(name, { path: '/' });
  }
  res.redirect('/');
});

app.get('/api/state', (req, res) => {
  const cart = parseCart(req.cookies.cart);
  const ident = parseIdentity(req.cookies.identity);
  const authz = parseAuthz(req.cookies.authz);
  let vault = null;
  try {
    vault = decryptVault(req.cookies.vault);
  } catch {
    vault = { error: 'decrypt failed' };
  }
  const L = parseLegacy(req);
  res.json({ cart, ident, authz, vault, legacy: { ok: L.ok, hasAdmin: L.data.includes('user=admin') } });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[harborcart] listening on ${PORT}`);
});
