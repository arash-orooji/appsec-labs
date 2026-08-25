/**
 * Local WAF gate — applies the same detection logic as the LocalStack
 * AWS WAF Classic (waf-regional) WebACL.
 *
 * LocalStack Community does not support WAFv2. This lab stores the ACL
 * with WAF Classic APIs; this proxy enforces the rules on live traffic
 * because LocalStack does not front the application HTTP port.
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3000);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'XSS-CSRF-Protection';

const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ||
  'http://localhost:3000,http://127.0.0.1:3000,http://localhost:8080,http://127.0.0.1:8080'
)
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

function urlDecodeRepeated(value) {
  let current = String(value ?? '');
  for (let i = 0; i < 3; i += 1) {
    try {
      const next = decodeURIComponent(current.replace(/\+/g, ' '));
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

function htmlEntityDecode(value) {
  return String(value ?? '')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&#39;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(Number(dec)))
    .replace(/&amp;/gi, '&');
}

function normalizeForXss(value) {
  return htmlEntityDecode(urlDecodeRepeated(value))
    .toLowerCase()
    .replace(/\0/g, '')
    .replace(/[\u0000-\u001f]/g, '');
}

const XSS_PATTERNS = [
  /<\s*script\b/,
  /<\s*svg\b/,
  /<\s*img\b/,
  /<\s*iframe\b/,
  /<\s*object\b/,
  /<\s*embed\b/,
  /<\s*link\b/,
  /<\s*style\b/,
  /<\s*meta\b/,
  /javascript\s*:/,
  /vbscript\s*:/,
  /expression\s*\(/,
  /\bon(?:error|load|click|focus|mouseover|mouseenter|submit|toggle|animationstart)\s*=/,
];

function xssHit(value) {
  const normalized = normalizeForXss(value);
  return XSS_PATTERNS.some((re) => re.test(normalized));
}

function collectXssInputs(req, rawUrl, body) {
  const inputs = [rawUrl, body];
  try {
    const parsed = new URL(rawUrl, 'http://waf.local');
    inputs.push(parsed.pathname, parsed.search, parsed.searchParams.get('q') || '');
    parsed.searchParams.forEach((v) => inputs.push(v));
  } catch {
    // ignore malformed URLs — rawUrl is still inspected
  }
  return inputs;
}

function evaluateXss(req, rawUrl, body) {
  const haystacks = collectXssInputs(req, rawUrl, body);
  for (const item of haystacks) {
    if (item && xssHit(item)) {
      return {
        rule: 'Block-XSS-Rule',
        reason: 'XSS match in query string, URI, or body (WAF Classic XssMatchSet)',
      };
    }
  }
  return null;
}

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function isAllowedOrigin(origin, referer) {
  const values = [origin, referer].map((v) => v.toLowerCase());
  return ALLOWED_ORIGINS.some((allowed) => values.some((v) => v.startsWith(allowed)));
}

function evaluateCsrf(req, rawUrl) {
  if (String(req.method || '').toUpperCase() !== 'POST') return null;
  let pathname = rawUrl.split('?')[0];
  try {
    pathname = new URL(rawUrl, 'http://waf.local').pathname;
  } catch {
    // keep pathname from split
  }
  if (pathname !== '/update-email') return null;

  const origin = header(req, 'origin');
  const referer = header(req, 'referer');
  if (isAllowedOrigin(origin, referer)) return null;

  return {
    rule: 'Block-CSRF-Rule',
    reason:
      'POST /update-email without a same-origin Origin/Referer (WAF Classic negated ByteMatch on Origin)',
  };
}

function evaluateWaf(req, rawUrl, body) {
  const findings = [];
  const xss = evaluateXss(req, rawUrl, body);
  if (xss) findings.push(xss);
  const csrf = evaluateCsrf(req, rawUrl);
  if (csrf) findings.push(csrf);
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
    const body = bodyBuf.toString('utf8');
    const findings = evaluateWaf(req, req.url || '/', body);

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
    upstream.on('timeout', () => {
      upstream.destroy(new Error('upstream timeout'));
    });
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
  console.log(
    `[waf-proxy] listening on ${PORT}, upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}, acl=${WEB_ACL_NAME}`
  );
  console.log('[waf-proxy] engine=AWS WAF Classic (waf-regional) — LocalStack Community (no WAFv2)');
});
