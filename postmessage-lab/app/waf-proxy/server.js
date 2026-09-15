/**
 * WAF VIP for HarborLink.
 *
 * Rewrites listeners-vuln.js to the secure bundle and rejects forged
 * postMessage dispatches (weak origins, null, proto merge, dangerous ops).
 */
const http = require('http');

const PORT = Number(process.env.PORT || 8880);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3800);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'PostMessage-Protection';

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function pathnameOf(rawUrl) {
  try {
    return new URL(rawUrl || '/', 'http://waf.local').pathname;
  } catch {
    return String(rawUrl || '/').split('?')[0];
  }
}

function evaluateWaf(req, body) {
  const findings = [];
  const path = pathnameOf(req.url);
  const raw = String(body || '');
  let msg = {};
  try {
    msg = JSON.parse(raw);
  } catch {
    msg = {};
  }
  const origin = String(msg.origin || '');
  const data = msg.data && typeof msg.data === 'object' ? msg.data : {};
  const op = String(data.op || '');
  const blob = `${raw}\n${JSON.stringify(msg)}`;

  if (path === '/api/dispatch-all') {
    findings.push({
      rule: 'Block-PostMessage-Gadget-Sweep',
      reason: 'dispatch-all replays every vulnerable gadget',
    });
    return findings;
  }

  if (path !== '/api/dispatch') return findings;

  if (op === 'banner') {
    findings.push({
      rule: 'Block-Unpinned-PostMessage-Origin',
      reason: 'op=banner accepted from any origin (HTML sink)',
    });
  }
  if (op === 'hello' || /"targetOrigin"\s*:\s*"\*"/.test(blob)) {
    findings.push({
      rule: 'Block-Wildcard-Target-Origin',
      reason: 'hello triggers session leak with targetOrigin *',
    });
  }
  if (origin.includes('harbor-link') && origin !== 'http://harbor-link.lab' && origin !== 'https://harbor-link.lab') {
    findings.push({
      rule: 'Block-Weak-Origin-Includes',
      reason: `origin ${origin} matches includes('harbor-link')`,
    });
  }
  if (origin.startsWith('http://127.0.0.1:3800') && origin !== 'http://127.0.0.1:3800') {
    findings.push({
      rule: 'Block-Weak-Origin-Prefix',
      reason: `origin ${origin} bypasses startsWith(selfOrigin)`,
    });
  }
  if (!origin || origin === 'null') {
    findings.push({
      rule: 'Block-Null-Origin-Message',
      reason: 'Origin null / missing (sandboxed iframe)',
    });
  }
  if (/harbor-link\.lab$/.test(origin) && !/^https?:\/\/harbor-link\.lab$/.test(origin)) {
    findings.push({
      rule: 'Block-Weak-Origin-Suffix',
      reason: `origin ${origin} matches /harbor-link\\.lab$/`,
    });
  }
  if (op === 'cfg' || /__proto__/.test(blob)) {
    findings.push({
      rule: 'Block-PostMessage-Prototype-Merge',
      reason: 'cfg / __proto__ deep-merge gadget',
    });
  }
  if (op === 'go') {
    findings.push({
      rule: 'Block-Dangerous-PostMessage-Op',
      reason: 'op=go assigns a URL from the message',
    });
  }
  return findings;
}

function blocked(findings) {
  return JSON.stringify(
    {
      message: 'Blocked by AWS WAF Classic (lab simulation)',
      webAcl: WEB_ACL_NAME,
      api: 'waf-regional',
      matches: findings,
    },
    null,
    2
  );
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.url === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end('ok');
      return;
    }

    const bodyBuf = await readRequestBody(req);
    const body = bodyBuf.toString('utf8');
    const findings = evaluateWaf(req, body);
    if (findings.length) {
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '));
      const json = blocked(findings);
      res.writeHead(403, {
        'Content-Type': 'application/json; charset=utf-8',
        'X-WAF-Action': 'BLOCK',
        'X-WAF-WebACL': WEB_ACL_NAME,
        'Content-Length': Buffer.byteLength(json),
        Connection: 'close',
        'Access-Control-Allow-Origin': header(req, 'origin') || '*',
      });
      res.end(json);
      return;
    }

    let path = req.url;
    if (pathnameOf(path) === '/listeners-vuln.js') {
      path = '/listeners-secure.js';
    }

    const headers = { ...req.headers, host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}` };
    delete headers.connection;
    delete headers['keep-alive'];
    delete headers['transfer-encoding'];
    headers.connection = 'close';

    const upstream = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        method: req.method,
        path,
        headers,
        agent: false,
        timeout: 10_000,
      },
      (upRes) => {
        const outHeaders = { ...upRes.headers };
        delete outHeaders.connection;
        delete outHeaders['keep-alive'];
        delete outHeaders['transfer-encoding'];
        outHeaders.connection = 'close';
        res.writeHead(upRes.statusCode || 502, outHeaders);
        upRes.pipe(res);
      }
    );
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', (err) => {
      if (res.headersSent) return;
      res.writeHead(502, { 'Content-Type': 'text/plain', Connection: 'close' });
      res.end(`Upstream error: ${err.message}`);
    });
    if (bodyBuf.length) upstream.write(bodyBuf);
    upstream.end();
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain', Connection: 'close' });
    res.end(String(err.message));
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[waf-proxy] VIP on ${PORT} → ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log('[waf-proxy] rewrite listeners-vuln.js → listeners-secure.js');
});
