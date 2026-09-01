/**
 * VaultPay — Session Puzzling 2FA bypass lab.
 *
 * After a correct password the app sets session.confirmed = true
 * ("we know who you are") and asks for a 2FA code. Backup-code and
 * settings endpoints only check `confirmed`, not `twoFactorComplete`.
 *
 * That is the same session-variable mix-up described in:
 * https://dzone.com/articles/using-session-puzzling-to-bypass-two-factor-authen
 *
 * Attack:
 *   1. POST /login with alice / letmein
 *   2. GET  /settings/backup-codes  (or /api/backup-codes) while 2FA is pending
 *   3. POST /2fa with a stolen backup code
 *   4. GET  /dashboard → FLAG{session-puzzling-2fa-bypass}
 */
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const PORT = Number(process.env.PORT || 3300);
const FLAG = 'FLAG{session-puzzling-2fa-bypass}';

const USERS = {
  alice: {
    password: 'letmein',
    displayName: 'Alice Nguyen',
    phone: '+1 ••• ••• 4419',
    twoFactorEnabled: true,
    backupCodes: ['VAULT-7K2M-9QPD', 'VAULT-3N8R-W4HJ', 'VAULT-1C6T-B5YF'],
  },
};

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'vaultpay-lab-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', path: '/' },
  })
);

function setAuthStepCookie(res, step) {
  res.cookie('auth_step', step, {
    path: '/',
    httpOnly: false,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  });
}

function clearAuthStepCookie(res) {
  res.clearCookie('auth_step', { path: '/' });
}

function newOtp() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: Georgia, serif; max-width: 720px; margin: 2rem auto; line-height: 1.5; color: #1a1a1a; }
    code, pre, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.92em; }
    a { color: #0f4c81; }
    nav a { margin-right: 1rem; }
    h1 { font-size: 1.7rem; }
    label { display: block; margin: 0.6rem 0 0.2rem; font-weight: 600; }
    input[type=text], input[type=password] { width: 100%; max-width: 320px; padding: 0.45rem 0.5rem; font: inherit; }
    button, .btn { display: inline-block; margin-top: 0.9rem; padding: 0.45rem 0.9rem; font: inherit; background: #0f4c81; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; }
    .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
    .err { border-left: 4px solid #b91c1c; padding: 0.75rem 1rem; background: #fef2f2; }
    .puzzle { border-left: 4px solid #6d28d9; padding: 0.75rem 1rem; background: #f5f3ff; }
    ul.codes { list-style: none; padding: 0; }
    ul.codes li { font-family: Consolas, ui-monospace, monospace; background: #f3f4f6; display: inline-block; margin: 0.25rem 0.4rem 0.25rem 0; padding: 0.35rem 0.6rem; }
    .muted { color: #4b5563; font-size: 0.95rem; }
    footer { margin-top: 2.5rem; font-size: 0.85rem; color: #6b7280; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/login">Login</a>
    <a href="/2fa">2FA</a>
    <a href="/settings">Settings</a>
    <a href="/dashboard">Dashboard</a>
    <a href="/logout">Log out</a>
  </nav>
  ${body}
  <footer>
    VaultPay lab — session puzzling / 2FA bypass.
    WAF gate: <a href="http://localhost:8380">:8380</a>
  </footer>
</body>
</html>`;
}

function sessionPuzzle(req) {
  const s = req.session || {};
  return `
    <div class="puzzle">
      <strong>Session puzzle</strong>
      <pre class="mono" style="margin:0.4rem 0 0">username            = ${s.username || '(unset)'}
confirmed           = ${s.confirmed === true ? 'true' : 'false'}   // set after password
twoFactorComplete   = ${s.twoFactorComplete === true ? 'true' : 'false'}   // set after 2FA
twoFactorRequired   = ${s.twoFactorRequired === true ? 'true' : 'false'}</pre>
      <p class="muted" style="margin:0.5rem 0 0">
        Settings and backup codes only check <code>confirmed</code>.
        The dashboard checks <code>twoFactorComplete</code>. Same session, two meanings.
      </p>
    </div>`;
}

function flash(query) {
  if (query.error) return `<p class="err">${escapeHtml(String(query.error))}</p>`;
  if (query.info) return `<p class="ok">${escapeHtml(String(query.info))}</p>`;
  return '';
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, lab: 'session-puzzling-2fa' });
});

app.get('/', (req, res) => {
  res.send(
    layout(
      'VaultPay — Session Puzzling Lab',
      `
      <h1>VaultPay</h1>
      <p>Sign in with your password. If 2FA is enabled we text a code to your phone
      before we open the dashboard. Lost your phone? Use a backup code.</p>
      ${sessionPuzzle(req)}
      <p>Demo account: <code>alice</code> / <code>letmein</code> (2FA on).</p>
      <p><a class="btn" href="/login">Sign in</a></p>
      <h2>What this lab shows</h2>
      <ol>
        <li>Victim (or attacker with a stolen password) submits email + password.</li>
        <li>Session is marked <code>confirmed = true</code> and a 2FA prompt is shown.</li>
        <li>Backup-code settings are reachable in that half-logged-in state.</li>
        <li>Stolen backup codes complete 2FA. Dashboard unlocks without the SMS/TOTP.</li>
      </ol>`
    )
  );
});

app.get('/login', (req, res) => {
  if (req.session.twoFactorComplete) return res.redirect('/dashboard');
  if (req.session.username && req.session.twoFactorRequired) return res.redirect('/2fa');
  res.send(
    layout(
      'Sign in — VaultPay',
      `
      <h1>Sign in</h1>
      ${flash(req.query)}
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" value="alice" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" value="letmein" />
        <button type="submit">Continue</button>
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
    if (err) {
      console.error(err);
      return res.status(500).send('session error');
    }
    req.session.username = username;
    // SESSION PUZZLE: "confirmed" here means "password accepted", not "2FA done".
    req.session.confirmed = true;
    req.session.twoFactorRequired = user.twoFactorEnabled;
    req.session.twoFactorComplete = !user.twoFactorEnabled;
    if (user.twoFactorEnabled) {
      req.session.otp = newOtp();
      setAuthStepCookie(res, 'pending_2fa');
      console.log(`[vaultpay] SMS to ${user.phone} for ${username}: ${req.session.otp}`);
      return req.session.save(() => res.redirect('/2fa'));
    }
    setAuthStepCookie(res, 'complete');
    return req.session.save(() => res.redirect('/dashboard'));
  });
});

app.get('/2fa', (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  if (req.session.twoFactorComplete) return res.redirect('/dashboard');
  const method = String(req.query.method || 'sms');
  const backupForm =
    method === 'backup'
      ? `
        <form method="post" action="/2fa">
          <input type="hidden" name="method" value="backup" />
          <label for="backup">Backup code</label>
          <input id="backup" name="backup" type="text" autocomplete="one-time-code" placeholder="VAULT-XXXX-XXXX" />
          <button type="submit">Verify backup code</button>
        </form>
        <p class="muted"><a href="/2fa">Use the SMS code instead</a></p>`
      : `
        <form method="post" action="/2fa">
          <input type="hidden" name="method" value="sms" />
          <label for="code">6-digit code</label>
          <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" />
          <button type="submit">Verify</button>
        </form>
        <p class="muted"><a href="/2fa?method=backup">Lost your phone? Use a backup code</a></p>`;

  res.send(
    layout(
      'Two-factor authentication — VaultPay',
      `
      <h1>Two-factor authentication</h1>
      ${flash(req.query)}
      <p>We sent a code to <strong>${escapeHtml(USERS[req.session.username].phone)}</strong>.
      Password is accepted; the dashboard stays locked until this step succeeds.</p>
      ${sessionPuzzle(req)}
      ${backupForm}
      <p class="muted">Account settings stay linked in the nav — the bug is that they
      still work while <code>twoFactorComplete</code> is false.</p>`
    )
  );
});

app.post('/2fa', (req, res) => {
  if (!req.session.username || !req.session.confirmed) {
    return res.redirect('/login');
  }
  if (req.session.twoFactorComplete) return res.redirect('/dashboard');

  const user = USERS[req.session.username];
  const method = String(req.body.method || 'sms');
  const code = String(req.body.code || '').replace(/\s/g, '');
  const backup = String(req.body.backup || '')
    .trim()
    .toUpperCase();

  let ok = false;
  if (method === 'backup' || backup) {
    if (user.backupCodes.includes(backup)) {
      ok = true;
      console.log(`[vaultpay] backup code accepted for ${req.session.username}: ${backup}`);
    }
  } else if (code && code === req.session.otp) {
    ok = true;
  }

  if (!ok) {
    return res.redirect('/2fa?error=' + encodeURIComponent('Invalid code. Try again.'));
  }

  req.session.twoFactorComplete = true;
  req.session.otp = undefined;
  setAuthStepCookie(res, 'complete');
  req.session.save(() => res.redirect('/dashboard'));
});

function requireConfirmed(req, res, next) {
  if (req.session.confirmed === true) return next();
  if (req.accepts('html')) return res.redirect('/login');
  return res.status(401).json({ error: 'not confirmed' });
}

function requireFullAuth(req, res, next) {
  if (req.session.twoFactorComplete === true) return next();
  if (req.session.username) return res.redirect('/2fa');
  return res.redirect('/login');
}

app.get('/settings', requireConfirmed, (req, res) => {
  res.send(
    layout(
      'Settings — VaultPay',
      `
      <h1>Account settings</h1>
      <p>This page only checks <code>session.confirmed</code>. After a password login
      you can open it <em>before</em> 2FA — the access-control gap from the article.</p>
      ${sessionPuzzle(req)}
      <ul>
        <li><a href="/settings/backup-codes">View backup codes</a></li>
      </ul>`
    )
  );
});

app.get('/settings/backup-codes', requireConfirmed, (req, res) => {
  const user = USERS[req.session.username];
  const items = user.backupCodes.map((c) => `<li>${escapeHtml(c)}</li>`).join('');
  res.send(
    layout(
      'Backup codes — VaultPay',
      `
      <h1>Backup codes</h1>
      <p class="warn">VULNERABLE: served because <code>session.confirmed === true</code>,
      not because 2FA finished. Copy a code, then finish login at
      <a href="/2fa?method=backup">the backup-code prompt</a>.</p>
      ${sessionPuzzle(req)}
      <ul class="codes">${items || '<li><em>No unused codes left.</em></li>'}</ul>`
    )
  );
});

app.get('/api/backup-codes', requireConfirmed, (req, res) => {
  const user = USERS[req.session.username];
  res.json({
    username: req.session.username,
    twoFactorComplete: req.session.twoFactorComplete === true,
    confirmed: req.session.confirmed === true,
    codes: user.backupCodes.slice(),
  });
});

app.get('/GetBackupCodes', requireConfirmed, (req, res) => {
  const user = USERS[req.session.username];
  res.json({ BackupCodes: user.backupCodes.slice() });
});

app.get('/dashboard', requireFullAuth, (req, res) => {
  const user = USERS[req.session.username];
  res.send(
    layout(
      'Dashboard — VaultPay',
      `
      <h1>Welcome, ${escapeHtml(user.displayName)}</h1>
      <p class="ok">Fully authenticated. 2FA is complete.</p>
      ${sessionPuzzle(req)}
      <p>Checking balance… <strong>$12,480.17</strong></p>
      <p>Flag: <code class="mono">${FLAG}</code></p>`
    )
  );
});

app.get('/lab/otp', (req, res) => {
  if (req.headers['x-lab-instructor'] !== '1') {
    return res.status(404).json({ error: 'not found' });
  }
  if (!req.session.otp) return res.status(400).json({ error: 'no pending otp' });
  res.json({ otp: req.session.otp });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    clearAuthStepCookie(res);
    res.clearCookie('sid', { path: '/' });
    res.redirect('/login?info=' + encodeURIComponent('Signed out.'));
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[vaultpay] listening on ${PORT}`);
  console.log('[vaultpay] demo user alice / letmein (2FA on)');
});
