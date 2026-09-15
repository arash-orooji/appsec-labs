/**
 * HarborLink — advanced window.postMessage lab.
 *
 * Partner widgets talk to the portal with postMessage. The vulnerable
 * listeners skip origin pinning, send secrets with targetOrigin '*',
 * use includes/startsWith/suffix tests, allow Origin null, deep-merge
 * JSON (prototype pollution), and navigate from op=go.
 */
const express = require('express');
const { FLAGS, STAGES, handleVulnerable, handleSecure, trophy } = require('./handlers');

const PORT = Number(process.env.PORT || 3800);
const TOKEN = process.env.SESSION_TOKEN || 'alice-session-token';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

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
    body { font-family: Georgia, serif; max-width: 960px; margin: 2rem auto; line-height: 1.5; color: #1a1714; }
    code, pre, textarea { font-family: Consolas, ui-monospace, monospace; font-size: 0.88em; }
    a { color: #9a3412; }
    nav a { margin-right: 0.85rem; }
    button, .btn { font: inherit; padding: 0.4rem 0.75rem; background: #9a3412; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 0.2rem 0.3rem 0.2rem 0; }
    button.alt { background: #7c2d12; }
    .warn { border-left: 4px solid #b45309; padding: 0.7rem 0.9rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.7rem 0.9rem; background: #ecfdf5; }
    .lab { border-left: 4px solid #9a3412; padding: 0.7rem 0.9rem; background: #fff7ed; }
    table { border-collapse: collapse; width: 100%; margin: 0.7rem 0; }
    th, td { text-align: left; padding: 0.35rem 0.45rem; border-bottom: 1px solid #e7e5e4; vertical-align: top; }
    iframe.sink { width: 100%; min-height: 12rem; border: 1px solid #e7e5e4; background: #fff; }
    #sink { min-height: 3rem; padding: 0.5rem; border: 1px dashed #a8a29e; }
    footer { margin-top: 2rem; font-size: 0.85rem; color: #78716c; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/workbench">Workbench</a>
    <a href="/portal">Portal</a>
  </nav>
  ${body}
  <footer>
    HarborLink — postMessage lab. <code>event.origin</code> is the anti-CSRF signal.
    VIP: <a href="http://127.0.0.1:8880/workbench">WAF :8880</a>
    · Attacker: <a href="http://127.0.0.1:3899">:3899</a>
  </footer>
</body>
</html>`;
}

function listenerBundle(mode) {
  const handler = mode === 'secure' ? 'handleSecure' : 'handleVulnerable';
  const src = require('fs')
    .readFileSync(require('path').join(__dirname, 'handlers.js'), 'utf8')
    .replace(/if \(typeof module[\s\S]*$/, '');
  return `/* HarborLink listeners (${mode}) */
${src}
window.HARBOR_TOKEN = ${JSON.stringify(TOKEN)};
window.PM_FLAGS = window.PM_FLAGS || [];
window.addEventListener('message', function (ev) {
  var ctx = {
    selfOrigin: location.origin,
    token: window.HARBOR_TOKEN,
    setHtml: function (h) {
      var el = document.getElementById('sink');
      if (el) el.innerHTML = h;
    },
    navigate: function (u) {
      var el = document.getElementById('navlog');
      if (el) el.textContent = u;
    }
  };
  var out = ${handler}(ev, ctx);
  window.PM_FLAGS = window.PM_FLAGS.concat(out.flags || []);
  var box = document.getElementById('flags');
  if (box) box.textContent = window.PM_FLAGS.join('\\n') || 'none';
  (out.replies || []).forEach(function (r) {
    if (ev.source) ev.source.postMessage(r.data, r.targetOrigin);
  });
});
`;
}

app.get('/health', (_req, res) => res.type('text').send('ok'));
app.get('/listeners-vuln.js', (_req, res) => {
  res.type('application/javascript').send(listenerBundle('vuln'));
});
app.get('/listeners-secure.js', (_req, res) => {
  res.type('application/javascript').send(listenerBundle('secure'));
});

app.get('/api/stages', (_req, res) => res.json({ stages: STAGES, flags: FLAGS }));

app.post('/api/dispatch', (req, res) => {
  const origin = req.body && req.body.origin != null ? String(req.body.origin) : '';
  const data = req.body && req.body.data;
  const ctx = { selfOrigin: `http://127.0.0.1:${PORT}`, token: TOKEN };
  const first = handleVulnerable({ origin, data }, ctx);
  let flags = first.flags.slice();
  for (const r of first.replies) {
    if (r.targetOrigin === '*') {
      const second = handleVulnerable({ origin: ctx.selfOrigin, data: r.data }, ctx);
      flags = flags.concat(second.flags);
    }
  }
  flags = trophy(flags);
  res.json({ flags, replies: first.replies, blocked: first.blocked || null });
});

app.post('/api/dispatch-all', (req, res) => {
  const ctx = { selfOrigin: `http://127.0.0.1:${PORT}`, token: TOKEN };
  let flags = [];
  for (const stage of STAGES) {
    const first = handleVulnerable({ origin: stage.origin, data: stage.data }, ctx);
    flags = flags.concat(first.flags);
    for (const r of first.replies) {
      if (r.targetOrigin === '*') {
        flags = flags.concat(handleVulnerable({ origin: ctx.selfOrigin, data: r.data }, ctx).flags);
      }
    }
  }
  res.json({ flags: trophy(flags) });
});

app.get('/', (_req, res) => {
  const rows = STAGES.map(
    (s) =>
      `<tr><td>${escapeHtml(s.title)}</td><td><code>${escapeHtml(s.origin)}</code></td><td><code>${escapeHtml(JSON.stringify(s.data))}</code></td><td><code>${escapeHtml(s.flag)}</code></td></tr>`
  ).join('');
  res.type('html').send(
    layout(
      'HarborLink — postMessage lab',
      `
      <h1>HarborLink partner portal</h1>
      <p>Widgets talk to the portal with <code>window.postMessage</code>.
      The vulnerable listeners treat a <code>MessageEvent</code> like a first-party
      function call.</p>
      <div class="lab">
        <code>event.origin</code> is the only browser-enforced sender identity.
        <code>targetOrigin: '*'</code> broadcasts secrets. <code>includes</code> /
        <code>startsWith</code> / suffix regexes are not allowlists.
        <code>Origin: null</code> is a sandboxed iframe, not you.
      </div>
      <p><a class="btn" href="/workbench">Open the workbench</a></p>
      <table>
        <thead><tr><th>Stage</th><th>Forged origin</th><th>Message</th><th>Flag</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `
    )
  );
});

app.get('/portal', (_req, res) => {
  res.type('html').send(
    layout(
      'Portal — HarborLink',
      `
      <h1>Portal sink</h1>
      <p class="warn">Listening with <code>listeners-vuln.js</code>. Session token is
      <code>${escapeHtml(TOKEN)}</code>.</p>
      <div id="sink"><em>banner sink</em></div>
      <p>Navigate log: <code id="navlog">none</code></p>
      <pre class="ok" id="flags">none</pre>
      <script src="/listeners-vuln.js"></script>
      <script>
        if (location.search.indexOf('announce=1') !== -1 && window.opener) {
          window.opener.postMessage({ op: 'session', token: window.HARBOR_TOKEN, flag: ${JSON.stringify(FLAGS.wildcard)} }, '*');
        }
      </script>
    `
    )
  );
});

app.get('/workbench', (_req, res) => {
  const buttons = STAGES.map((s) => `<button type="button" data-stage="${escapeHtml(s.key)}">${escapeHtml(s.title)}</button>`).join('');
  res.type('html').send(
    layout(
      'Workbench — HarborLink',
      `
      <h1>postMessage workbench</h1>
      <p class="warn">Stages 1–2 and 5, 7, 8 also run as real cross-origin
      <code>postMessage</code> from <code>:3899</code>. Weak origin tests (3, 4, 6)
      use <code>/api/dispatch</code> because a browser cannot spoof <code>event.origin</code>.</p>
      <p>${buttons}
        <button type="button" id="all" class="alt">★ run all (dispatch)</button>
      </p>
      <h2>Attacker suite (real postMessage)</h2>
      <iframe class="sink" id="suite" src="http://127.0.0.1:3899/suite?target=http://127.0.0.1:${PORT}/portal"></iframe>
      <h2>Dispatch flags</h2>
      <pre class="ok" id="flags">none yet</pre>
      <script>
        const flagsEl = document.getElementById('flags');
        async function dispatch(stage) {
          const r = await fetch('/api/dispatch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ origin: stage.origin, data: stage.data })
          });
          const data = await r.json();
          flagsEl.textContent = (r.ok ? '' : 'HTTP ' + r.status + '\\n') + JSON.stringify(data, null, 2);
        }
        fetch('/api/stages').then(r => r.json()).then(info => {
          document.querySelectorAll('[data-stage]').forEach(btn => {
            btn.onclick = () => {
              const stage = info.stages.find(s => s.key === btn.getAttribute('data-stage'));
              if (stage) dispatch(stage);
            };
          });
          document.getElementById('all').onclick = async () => {
            const r = await fetch('/api/dispatch-all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
            const data = await r.json();
            flagsEl.textContent = (r.ok ? '' : 'HTTP ' + r.status + '\\n') + JSON.stringify(data, null, 2);
          };
        });
      </script>
    `
    )
  );
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[harbor-link] postMessage lab on ${PORT}`);
});
