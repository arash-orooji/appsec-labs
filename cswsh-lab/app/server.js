/**
 * Harbor Markets — Cross-Site WebSocket Hijacking lab origin.
 *
 * Three authenticated sockets, three handshake mistakes:
 *   /ws/desk    — cookie session, no Origin check (classic CSWSH)
 *   /ws/quotes  — Origin must only *contain* "harbor" (substring bypass)
 *   /ws/iframe  — Origin: null is treated as first-party (sandboxed iframe)
 *
 * The session cookie is not SameSite=Strict. A page on another origin
 * (or port) can open the socket; the browser attaches sid automatically.
 */
const http = require('http');
const express = require('express');
const session = require('express-session');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 3600);
const FLAG_CLASSIC = 'FLAG{cswsh-classic}';
const FLAG_POSITIONS = 'FLAG{cswsh-positions}';
const FLAG_ORDER = 'FLAG{cswsh-forced-order}';
const FLAG_ORIGIN = 'FLAG{cswsh-origin-bypass}';
const FLAG_NULL = 'FLAG{cswsh-null-origin}';

const USERS = {
  alice: {
    password: 'letmein',
    name: 'Alice Nguyen',
    cash: 84210.55,
    book: [
      { symbol: 'HBR', qty: 400, mark: 128.4 },
      { symbol: 'NORD', qty: 120, mark: 41.7 },
    ],
  },
};

const sessionMiddleware = session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'harbor-markets-cswsh-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,
    secure: false,
    path: '/',
  },
});

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware);

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
    body { font-family: Georgia, serif; max-width: 820px; margin: 2rem auto; line-height: 1.5; color: #14201a; }
    code, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.92em; }
    a { color: #14532d; }
    nav a { margin-right: 0.9rem; }
    label { display: block; margin: 0.55rem 0 0.2rem; font-weight: 600; }
    input { font: inherit; padding: 0.4rem 0.5rem; max-width: 280px; width: 100%; }
    button, .btn { font: inherit; padding: 0.4rem 0.85rem; background: #14532d; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 0.7rem; }
    .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
    .err { border-left: 4px solid #b91c1c; padding: 0.75rem 1rem; background: #fef2f2; }
    .lab { border-left: 4px solid #6d28d9; padding: 0.75rem 1rem; background: #f5f3ff; }
    table { border-collapse: collapse; width: 100%; margin: 0.8rem 0; }
    th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #d1d5db; }
    #tape { font-family: Consolas, ui-monospace, monospace; font-size: 0.85rem; background: #0b1220; color: #bbf7d0; padding: 0.8rem 1rem; min-height: 8rem; white-space: pre-wrap; }
    footer { margin-top: 2.2rem; font-size: 0.85rem; color: #6b7280; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/login">Sign in</a>
    <a href="/desk">Desk</a>
    <a href="/logout">Sign out</a>
  </nav>
  ${body}
  <footer>
    Harbor Markets — CSWSH lab. Cookies authenticate the WebSocket; Origin is not a capability.
    VIP: <a href="http://127.0.0.1:8680">WAF :8680</a>
    · Attacker: <a href="http://127.0.0.1:3699">:3699</a>
  </footer>
</body>
</html>`;
}

app.get('/health', (_req, res) => {
  res.type('text').send('ok');
});

app.get('/', (_req, res) => {
  res.type('html').send(
    layout(
      'Harbor Markets — CSWSH Lab',
      `
      <h1>Harbor Markets</h1>
      <p>Live desk over <strong>WebSocket</strong>. After login the browser opens
      <code>ws://…/ws/desk</code> with the <code>sid</code> cookie. There is no CSRF token
      and the handshake does not pin <code>Origin</code>.</p>
      <div class="lab">
        Cross-Site WebSocket Hijacking is CSRF against the upgrade:
        a foreign page calls <code>new WebSocket('ws://127.0.0.1:3600/ws/desk')</code>,
        the browser attaches <code>sid</code>, and the attacker reads private frames
        and places orders. That is not XSS — the attacker’s origin never sees <code>document.cookie</code>.
      </div>
      <p>Demo account: <code>alice</code> / <code>letmein</code>. Use <strong>127.0.0.1</strong>
      (not localhost) so the attacker origin on :3699 is cross-origin but same-site enough
      for the lab cookie to ride along.</p>
      <p>
        <a class="btn" href="/login">Sign in</a>
        <a class="btn" href="http://127.0.0.1:3699/hijack">Open attacker page</a>
      </p>
      <div class="warn">
        Prefer the WAF VIP on <code>:8680</code> (exact Origin + <code>wst.</code> ticket).
        <code>:3600</code> is the vulnerable origin.
      </div>
    `
    )
  );
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/desk');
  res.type('html').send(
    layout(
      'Sign in — Harbor Markets',
      `
      <h1>Sign in</h1>
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" value="alice" autocomplete="username" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" value="letmein" autocomplete="current-password" />
        <button type="submit">Sign in</button>
      </form>
    `
    )
  );
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).type('html').send(
      layout('Sign in — Harbor Markets', `<p class="err">Unknown trader.</p><p><a href="/login">Try again</a></p>`)
    );
  }
  req.session.user = username;
  res.redirect('/desk');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid', { path: '/' });
    res.redirect('/');
  });
});

app.get('/desk', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const trader = USERS[req.session.user];
  const rows = trader.book
    .map((p) => `<tr><td>${escapeHtml(p.symbol)}</td><td>${p.qty}</td><td>${p.mark.toFixed(2)}</td></tr>`)
    .join('');
  res.type('html').send(
    layout(
      'Desk — Harbor Markets',
      `
      <h1>Trading desk</h1>
      <p class="ok">Signed in as ${escapeHtml(trader.name)}. Socket flag appears on the tape after the handshake.</p>
      <p>Cash: <strong>$${trader.cash.toFixed(2)}</strong></p>
      <table>
        <thead><tr><th>Symbol</th><th>Qty</th><th>Mark</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <h2>Live tape</h2>
      <div id="tape">connecting…</div>
      <script>
        (function () {
          const tape = document.getElementById('tape');
          const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
          const url = proto + '//' + location.host + '/ws/desk';
          const m = document.cookie.match(/(?:^|; )wst=([0-9a-f]{32})/i);
          const protocols = m ? ['wst.' + m[1]] : undefined;
          const ws = protocols ? new WebSocket(url, protocols) : new WebSocket(url);
          function line(obj) {
            tape.textContent += (typeof obj === 'string' ? obj : JSON.stringify(obj)) + '\\n';
          }
          tape.textContent = '';
          ws.onopen = function () { line('open ' + url); };
          ws.onerror = function () { line('error'); };
          ws.onclose = function (ev) { line('close ' + ev.code); };
          ws.onmessage = function (ev) { line(ev.data); };
        })();
      </script>
    `
    )
  );
});

function loadSession(req) {
  return new Promise((resolve) => {
    const dummy = {
      getHeader() {},
      setHeader() {},
      end() {},
    };
    sessionMiddleware(req, dummy, () => resolve(req.session));
  });
}

function rejectUpgrade(socket, status, message) {
  const body = JSON.stringify({ error: message });
  socket.write(
    `HTTP/1.1 ${status} ${status === 401 ? 'Unauthorized' : 'Forbidden'}\r\n` +
      'Content-Type: application/json; charset=utf-8\r\n' +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      'Connection: close\r\n\r\n' +
      body
  );
  socket.destroy();
}

function originOf(req) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === 'origin');
  return key ? String(req.headers[key]) : '';
}

function attachDeskHandlers(ws, req, extras) {
  const username = req.session.user;
  const trader = USERS[username];
  const send = (obj) => ws.send(JSON.stringify(obj));

  send({
    type: 'welcome',
    user: username,
    name: trader.name,
    ...extras,
  });

  ws.on('message', (raw) => {
    let msg = {};
    try {
      msg = JSON.parse(String(raw));
    } catch {
      send({ type: 'error', error: 'bad json' });
      return;
    }
    const op = String(msg.op || '');
    if (op === 'whoami') {
      send({ type: 'whoami', user: username, name: trader.name });
      return;
    }
    if (op === 'positions') {
      send({
        type: 'positions',
        user: username,
        cash: trader.cash,
        book: trader.book,
        flag: FLAG_POSITIONS,
      });
      return;
    }
    if (op === 'order') {
      const side = String(msg.side || 'sell');
      const symbol = String(msg.symbol || 'HBR');
      const qty = Number(msg.qty || 0);
      send({
        type: 'order-ack',
        side,
        symbol,
        qty,
        status: 'accepted',
        flag: FLAG_ORDER,
      });
      return;
    }
    send({ type: 'error', error: 'unknown op' });
  });
}

function handleProtocols(protocols) {
  const list = [...protocols];
  const ticket = list.find((p) => /^wst\.[0-9a-f]{32}$/i.test(p));
  if (ticket) return ticket;
  return list[0] || false;
}

const deskWss = new WebSocketServer({ noServer: true, handleProtocols });
const quotesWss = new WebSocketServer({ noServer: true, handleProtocols });
const iframeWss = new WebSocketServer({ noServer: true, handleProtocols });

deskWss.on('connection', (ws, req) => {
  attachDeskHandlers(ws, req, { channel: 'desk', flag: FLAG_CLASSIC });
});
quotesWss.on('connection', (ws, req) => {
  attachDeskHandlers(ws, req, { channel: 'quotes', flag: FLAG_ORIGIN });
});
iframeWss.on('connection', (ws, req) => {
  attachDeskHandlers(ws, req, { channel: 'iframe', flag: FLAG_NULL });
});

const server = http.createServer(app);

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  const path = String(req.url || '').split('?')[0];
  await loadSession(req);
  if (!req.session || !req.session.user) {
    rejectUpgrade(socket, 401, 'login required for websocket');
    return;
  }

  const origin = originOf(req);

  if (path === '/ws/desk') {
    deskWss.handleUpgrade(req, socket, head, (ws) => deskWss.emit('connection', ws, req));
    return;
  }

  if (path === '/ws/quotes') {
    if (!origin.toLowerCase().includes('harbor')) {
      rejectUpgrade(socket, 403, 'Origin must mention harbor');
      return;
    }
    quotesWss.handleUpgrade(req, socket, head, (ws) => quotesWss.emit('connection', ws, req));
    return;
  }

  if (path === '/ws/iframe') {
    if (origin && origin !== 'null') {
      rejectUpgrade(socket, 403, 'iframe channel expects Origin null');
      return;
    }
    iframeWss.handleUpgrade(req, socket, head, (ws) => iframeWss.emit('connection', ws, req));
    return;
  }

  rejectUpgrade(socket, 404, 'no such socket');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[harbor] listening on ${PORT} (CSWSH: cookie-auth WS, weak/missing Origin)`);
});
