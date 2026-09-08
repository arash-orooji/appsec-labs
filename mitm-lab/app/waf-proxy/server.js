/**
 * WAF VIP for Clearwire Bank.
 *
 * Real defense against this MitM: do not speak cleartext, mark session
 * cookies HttpOnly (+ Secure on HTTPS), and HMAC-wrap them so a stolen
 * raw sid from the HTTP origin cannot be replayed here.
 *
 * Requests that already passed through the lab hotspot (Via: Clearwire-MitM)
 * are blocked — stand-in for HSTS refusing the stripped channel.
 */
const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8580);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3500);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'MitM-Session-Protection';
const WAF_COOKIE_KEY = process.env.WAF_COOKIE_KEY || 'f5-waf-mitm-cookie-key';
const PROTECTED = new Set(['sid']);

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function hmacWrap(name, value) {
  const mac = crypto.createHmac('sha256', WAF_COOKIE_KEY).update(`${name}\0${value}`).digest('hex').slice(0, 32);
  return `w1.${mac}.${encodeURIComponent(value)}`;
}

function hmacUnwrap(name, wrapped) {
  const m = String(wrapped).match(/^w1\.([0-9a-f]{32})\.(.+)$/i);
  if (!m) return { ok: false, reason: 'missing WAF cookie wrap (w1.)' };
  const value = decodeURIComponent(m[2]);
  const expect = crypto.createHmac('sha256', WAF_COOKIE_KEY).update(`${name}\0${value}`).digest('hex').slice(0, 32);
  if (expect !== m[1].toLowerCase()) return { ok: false, reason: 'cookie HMAC mismatch' };
  return { ok: true, value };
}

function parseCookieHeader(raw) {
  const out = [];
  for (const part of String(raw || '')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    out.push({ name: part.slice(0, eq), value: part.slice(eq + 1) });
  }
  return out;
}

function evaluateWaf(req) {
  const findings = [];
  const via = header(req, 'via') + header(req, 'x-forwarded-by');
  if (/clearwire-mitm/i.test(via)) {
    findings.push({
      rule: 'Block-Ssl-Strip-Channel',
      reason: 'Via: Clearwire-MitM — session will not be issued on a stripped/hotspot channel',
    });
  }

  const forwarded = [];
  for (const { name, value } of parseCookieHeader(header(req, 'cookie'))) {
    if (!PROTECTED.has(name)) {
      forwarded.push(`${name}=${value}`);
      continue;
    }
    const inner = hmacUnwrap(name, value);
    if (!inner.ok) {
      findings.push({
        rule: 'Block-Cleartext-Session-Cookie',
        reason: `Cookie ${name}: ${inner.reason} (replay of a MitM-captured sid)`,
      });
      continue;
    }
    forwarded.push(`${name}=${inner.value}`);
  }
  return { findings, forwardedCookie: forwarded.join('; ') };
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
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Length': Buffer.byteLength(body),
      Connection: 'close',
    },
    body,
  };
}

function wrapSetCookieLine(line) {
  const segs = String(line).split(';');
  const pair = segs[0];
  const eq = pair.indexOf('=');
  if (eq <= 0) return line;
  const name = pair.slice(0, eq).trim();
  let value = pair.slice(eq + 1);
  const attrs = segs.slice(1);
  if (PROTECTED.has(name)) {
    try {
      value = hmacWrap(name, decodeURIComponent(value));
    } catch {
      value = hmacWrap(name, value);
    }
    const joined = attrs.join(';');
    if (!/httponly/i.test(joined)) attrs.push(' HttpOnly');
    if (!/samesite/i.test(joined)) attrs.push(' SameSite=Strict');
  }
  return [`${name}=${value}`, ...attrs].join(';');
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
    const { findings, forwardedCookie } = evaluateWaf(req);
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
    delete headers['keep-alive'];
    delete headers['transfer-encoding'];
    headers.connection = 'close';
    if (forwardedCookie) headers.cookie = forwardedCookie;
    else delete headers.cookie;

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
        outHeaders['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
        const sc = upRes.headers['set-cookie'];
        if (sc) {
          const list = Array.isArray(sc) ? sc : [sc];
          outHeaders['set-cookie'] = list.map(wrapSetCookieLine);
        }
        res.writeHead(upRes.statusCode || 502, outHeaders);
        upRes.pipe(res);
      }
    );
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', (err) => {
      if (res.headersSent) return;
      const msg = `Upstream error: ${err.message}`;
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
  console.log(`[waf-proxy] VIP on ${PORT} → ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log('[waf-proxy] HSTS + sid wrap + block Clearwire-MitM Via');
});
