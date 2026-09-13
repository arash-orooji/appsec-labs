/**
 * WAF gate for HarborHome DNS rebinding.
 *
 * SOP is hostname-based. After a rebind the browser still sends
 * Host: classic.rebind.lab (or a CNAME-bypass name). Pinning Host to
 * the real VIP names stops the stolen same-origin fetch even if DNS
 * flipped to 127.0.0.1 / 0.0.0.0.
 *
 * Also blocks Host literals used in PAT bypasses (0.0.0.0, *.local).
 */
const http = require('http');

const PORT = Number(process.env.PORT || 8980);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3900);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'DNS-Rebinding-Protection';

const ALLOWED_HOSTS = new Set(
  [
    '127.0.0.1',
    '127.0.0.1:3900',
    '127.0.0.1:8980',
    'localhost',
    'localhost:3900',
    'localhost:8980',
  ].map((h) => h.toLowerCase())
);

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function evaluateWaf(req) {
  const findings = [];
  const host = header(req, 'host').trim().toLowerCase();
  const hostName = host.split(':')[0];

  if (!ALLOWED_HOSTS.has(host)) {
    findings.push({
      rule: 'Block-Rebind-Host',
      reason: `Host '${host}' is not the HarborHome VIP (127.0.0.1 / localhost)`,
    });
  }
  if (hostName.endsWith('.rebind.lab') || hostName === 'rebind.lab') {
    findings.push({
      rule: 'Block-Rebind-Lab-Name',
      reason: 'Host matches attacker rebind zone',
    });
  }
  if (hostName === 'target.local' || hostName.endsWith('.local')) {
    findings.push({
      rule: 'Block-Internal-Local-Name',
      reason: 'Host is an internal .local name (CNAME-to-internal bypass)',
    });
  }
  if (hostName === '0.0.0.0') {
    findings.push({
      rule: 'Block-Unspecified-Address',
      reason: 'Host 0.0.0.0 (127/8 filter bypass)',
    });
  }
  return findings;
}

function blockedResponse(findings) {
  const body = JSON.stringify(
    {
      message: 'Blocked by AWS WAF Classic (lab simulation)',
      webAcl: WEB_ACL_NAME,
      api: 'waf-regional',
      matches: findings,
    },
    null,
    2
  );
  return {
    statusCode: 403,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-WAF-Action': 'BLOCK',
      'X-WAF-WebACL': WEB_ACL_NAME,
      'Content-Length': Buffer.byteLength(body),
      Connection: 'close',
    },
    body,
  };
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
    const bodyBuf = await readRequestBody(req);
    const findings = evaluateWaf(req);
    if (findings.length > 0) {
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '), header(req, 'host'));
      const blocked = blockedResponse(findings);
      res.writeHead(blocked.statusCode, blocked.headers);
      res.end(blocked.body);
      return;
    }

    console.log('[waf-proxy] ALLOW', req.method, req.url, header(req, 'host'));
    const headers = { ...req.headers, host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}` };
    delete headers.connection;
    delete headers['keep-alive'];
    delete headers['proxy-connection'];
    delete headers['transfer-encoding'];
    headers.connection = 'close';

    const upstream = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        method: req.method,
        path: req.url,
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
    upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
    upstream.on('error', (err) => {
      if (res.headersSent) return;
      const msg = `Upstream error: ${err.message}`;
      res.writeHead(502, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(msg) });
      res.end(msg);
    });
    if (bodyBuf.length) upstream.write(bodyBuf);
    upstream.end();
  } catch (err) {
    const msg = `WAF proxy error: ${err.message}`;
    res.writeHead(500, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(msg) });
    res.end(msg);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[waf-proxy] listening on ${PORT}, upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log('[waf-proxy] Host pin 127.0.0.1/localhost + block rebind.lab / .local / 0.0.0.0');
});
