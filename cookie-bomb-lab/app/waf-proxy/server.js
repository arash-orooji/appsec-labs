/**
 * WAF gate for the Cookie Bomb lab.
 * Blocks oversized query strings (planting) and oversized Cookie headers
 * (already-bombed clients), matching the WAF Classic WebACL.
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8280);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3200);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'Cookie-Bomb-Protection';
const MAX_QUERY_BYTES = Number(process.env.MAX_QUERY_BYTES || 1024);
const MAX_COOKIE_BYTES = Number(process.env.MAX_COOKIE_BYTES || 4096);
const MAX_PARAM_BYTES = Number(process.env.MAX_PARAM_BYTES || 512);

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function evaluateWaf(req) {
  const findings = [];
  let parsed;
  try {
    parsed = new URL(req.url || '/', 'http://waf.local');
  } catch {
    parsed = null;
  }

  const query = parsed ? parsed.search.replace(/^\?/, '') : '';
  const queryBytes = Buffer.byteLength(query);
  if (queryBytes >= MAX_QUERY_BYTES) {
    findings.push({
      rule: 'Block-Oversized-Query',
      reason: `Query string is ${queryBytes} bytes (limit ${MAX_QUERY_BYTES})`,
    });
  }

  if (parsed) {
    for (const [, value] of parsed.searchParams) {
      const n = Buffer.byteLength(value);
      if (n >= MAX_PARAM_BYTES) {
        findings.push({
          rule: 'Block-Oversized-Tracking-Param',
          reason: `Query parameter value is ${n} bytes (limit ${MAX_PARAM_BYTES})`,
        });
        break;
      }
    }
  }

  const cookie = header(req, 'cookie');
  const cookieBytes = Buffer.byteLength(cookie);
  if (cookieBytes >= MAX_COOKIE_BYTES) {
    findings.push({
      rule: 'Block-Oversized-Cookie',
      reason: `Cookie header is ${cookieBytes} bytes (limit ${MAX_COOKIE_BYTES})`,
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
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '));
      const blocked = blockedResponse(findings);
      res.writeHead(blocked.statusCode, blocked.headers);
      res.end(blocked.body);
      return;
    }

    console.log('[waf-proxy] ALLOW', req.method, req.url);
    const headers = { ...req.headers, host: `${UPSTREAM_HOST}:${UPSTREAM_PORT}` };
    delete headers.connection;
    const upstream = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        method: req.method,
        path: req.url,
        headers,
        timeout: 10_000,
      },
      (upRes) => {
        res.writeHead(upRes.statusCode || 502, upRes.headers);
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
  console.log('[waf-proxy] engine=AWS WAF Classic — blocks oversized query / Cookie headers');
});
