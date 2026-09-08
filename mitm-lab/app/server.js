/**
 * Clearwire Bank — MitM lab origin.
 *
 * HTTP only. Session cookie `sid` is not Secure and not HttpOnly, so a
 * proxy on the path can read Set-Cookie and a page-level injector can
 * read document.cookie. That is the classic public-Wi-Fi MitM:
 * intercept, capture the session, replay it.
 */
const express = require('express');
const session = require('express-session');

const PORT = Number(process.env.PORT || 3500);
const FLAG_HIJACK = 'FLAG{mitm-session-hijack}';
const FLAG_TRANSFER = 'FLAG{mitm-transfer-tamper}';

const USERS = {
  alice: { password: 'letmein', name: 'Alice Nguyen', balance: 12840.17 },
};

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'clearwire-lab-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      secure: false,
      sameSite: 'lax',
      path: '/',
    },
  })
);

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
    body { font-family: Georgia, serif; max-width: 760px; margin: 2rem auto; line-height: 1.5; color: #1a1a1a; }
    code, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.92em; }
    a { color: #0f4c81; }
    nav a { margin-right: 0.9rem; }
    label { display: block; margin: 0.55rem 0 0.2rem; font-weight: 600; }
    input { font: inherit; padding: 0.4rem 0.5rem; max-width: 280px; width: 100%; }
    button, .btn { font: inherit; padding: 0.4rem 0.85rem; background: #0f4c81; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 0.7rem; }
    .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
    .err { border-left: 4px solid #b91c1c; padding: 0.75rem 1rem; background: #fef2f2; }
    .lab { border-left: 4px solid #6d28d9; padding: 0.75rem 1rem; background: #f5f3ff; }
    footer { margin-top: 2.2rem; font-size: 0.85rem; color: #6b7280; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/login">Sign in</a>
    <a href="/dashboard">Dashboard</a>
    <a href="/transfer">Transfer</a>
    <a href="/logout">Sign out</a>
  </nav>
  ${body}
  <footer>
    Clearwire Bank — MitM lab (HTTP, session cookie not Secure / not HttpOnly).
    Real VIP: <a href="http://localhost:8580">WAF :8580</a>
    · Hotspot: <a href="http://localhost:3580">MitM :3580</a>
  </footer>
</body>
</html>`;
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, lab: 'mitm' });
});

app.get('/', (req, res) => {
  res.send(
    layout(
      'Clearwire Bank — MitM Lab',
      `
      <h1>Clearwire Bank</h1>
      <p>Mobile banking over the airport Wi-Fi. The site is plain
      <strong>HTTP</strong>. The session cookie <code>sid</code> is not
      <code>Secure</code> and not <code>HttpOnly</code>.</p>
      <div class="lab">
        A MitM sits between you and this origin: intercept, read
        <code>Set-Cookie</code>, replay the session. That is hijacking
        via cookie capture — not guessing the password.
      </div>
      <p>Demo account: <code>alice</code> / <code>letmein</code></p>
      <p><a class="btn" href="/login">Sign in</a>
         <a class="btn" href="http://localhost:3580/_mitm/">Attacker console</a></p>
      <p class="warn">Prefer the WAF VIP on :8580 (HSTS + cookie wrap).
      The hotspot proxy on :3580 is the attacker.</p>`
    )
  );
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(
    layout(
      'Sign in — Clearwire Bank',
      `
      <h1>Sign in</h1>
      ${req.query.error ? `<p class="err">${escapeHtml(req.query.error)}</p>` : ''}
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" value="alice" autocomplete="username" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" value="letmein" autocomplete="current-password" />
        <button type="submit">Sign in</button>
      </form>`
    )
  );
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.redirect('/login?error=' + encodeURIComponent('Invalid username or password.'));
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('session error');
    req.session.user = username;
    req.session.save(() => res.redirect('/dashboard'));
  });
});

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  if (req.accepts('html')) return res.redirect('/login');
  return res.status(401).json({ error: 'login required' });
}

app.get('/dashboard', requireAuth, (req, res) => {
  const user = USERS[req.session.user];
  res.send(
    layout(
      'Dashboard — Clearwire Bank',
      `
      <h1>Welcome, ${escapeHtml(user.name)}</h1>
      <p class="ok">Authenticated session. If an attacker captured <code>sid</code>,
      they see this page too.</p>
      <p>Available balance: <strong>$${user.balance.toFixed(2)}</strong></p>
      <p>Session flag: <code class="mono">${FLAG_HIJACK}</code></p>
      <p><a class="btn" href="/transfer">Send a transfer</a></p>`
    )
  );
});

app.get('/transfer', requireAuth, (req, res) => {
  res.send(
    layout(
      'Transfer — Clearwire Bank',
      `
      <h1>Transfer</h1>
      <p>Amount is taken from the POST body. A MitM on the path can change
      <code>amount</code> before it reaches us.</p>
      ${req.query.info ? `<p class="ok">${req.query.info}</p>` : ''}
      ${req.query.flag ? `<p class="ok">Flag: <code class="mono">${escapeHtml(req.query.flag)}</code></p>` : ''}
      <form method="post" action="/transfer">
        <label for="to">To</label>
        <input id="to" name="to" value="bob" />
        <label for="amount">Amount (USD)</label>
        <input id="amount" name="amount" value="25.00" />
        <button type="submit">Send</button>
      </form>`
    )
  );
});

app.post('/transfer', requireAuth, (req, res) => {
  const amount = Number(req.body.amount);
  const to = String(req.body.to || 'bob');
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.redirect('/transfer?info=' + encodeURIComponent('Invalid amount.'));
  }
  const user = USERS[req.session.user];
  const flag = amount >= 1000 ? FLAG_TRANSFER : '';
  const info = `Sent $${amount.toFixed(2)} to ${to}. Remaining $${user.balance.toFixed(2)}.`;
  const q = new URLSearchParams({ info });
  if (flag) q.set('flag', flag);
  res.redirect('/transfer?' + q.toString());
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid', { path: '/' });
    res.redirect('/login');
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[clearwire] listening on ${PORT} (HTTP, sid not Secure/HttpOnly)`);
});
