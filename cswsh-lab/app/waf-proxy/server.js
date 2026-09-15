/**
 * WAF VIP for Harbor Markets.
 *
 * CSWSH defense: pin the WebSocket handshake to this VIP's Origin, require
 * an HMAC ticket (wst) bound to the session cookie, reject Origin: null
 * and substring "harbor" lookalikes. HTTP responses wrap sid and issue wst.
 */
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8680);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3600);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'CSWSH-WebSocket-Protection';
const WAF_COOKIE_KEY = process.env.WAF_COOKIE_KEY || 'f5-waf-cswsh-cookie-key';
const ALLOWED_ORIGINS = new Set(
  (process.env.ALLOWED_ORIGINS || `http://127.0.0.1:${PORT},http://localhost:${PORT}`).split(',').map((s) => s.trim())
);

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

function ticketForSid(rawSid) {
  return crypto.createHmac('sha256', WAF_COOKIE_KEY).update(`wst\0${rawSid}`).digest('hex').slice(0, 32);
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

function isWsPath(req) {
  try {
    return new URL(req.url, 'http://waf.local').pathname.startsWith('/ws/');
  } catch {
    return String(req.url || '').startsWith('/ws/');
  }
}

function isWsUpgrade(req) {
  return /websocket/i.test(header(req, 'upgrade')) || isWsPath(req);
}

function evaluateWaf(req) {
  const findings = [];
  const forwarded = [];
  let rawSid = '';
  let wstCookie = '';

  for (const { name, value } of parseCookieHeader(header(req, 'cookie'))) {
    if (name === 'sid') {
      const inner = hmacUnwrap(name, value);
      if (!inner.ok) {
        findings.push({
          rule: 'Block-Cleartext-Session-Cookie',
          reason: `Cookie sid: ${inner.reason}`,
        });
        continue;
      }
      rawSid = inner.value;
      forwarded.push(`${name}=${inner.value}`);
      continue;
    }
    if (name === 'wst') {
      wstCookie = value;
      continue;
    }
    forwarded.push(`${name}=${value}`);
  }

  if (isWsUpgrade(req)) {
    const origin = header(req, 'origin');
    if (!origin || origin === 'null') {
      findings.push({
        rule: 'Block-Null-Origin-Websocket',
        reason: 'WebSocket upgrade with missing or null Origin',
      });
    } else if (!ALLOWED_ORIGINS.has(origin)) {
      if (/harbor/i.test(origin)) {
        findings.push({
          rule: 'Block-Weak-Origin-Bypass',
          reason: `Origin ${origin} contains "harbor" but is not the VIP allowlist`,
        });
      } else {
        findings.push({
          rule: 'Block-Cross-Origin-Websocket',
          reason: `Origin ${origin} is not the Harbor Markets VIP`,
        });
      }
    }

    const proto = header(req, 'sec-websocket-protocol');
    const fromProto = (proto.match(/wst\.([0-9a-f]{32})/i) || [])[1] || '';
    const presented = (fromProto || wstCookie || '').toLowerCase();
    if (!presented) {
      findings.push({
        rule: 'Block-Missing-Ws-Ticket',
        reason: 'Upgrade missing wst ticket (Sec-WebSocket-Protocol or wst cookie)',
      });
    } else if (!rawSid || presented !== ticketForSid(rawSid)) {
      findings.push({
        rule: 'Block-Ws-Ticket-Mismatch',
        reason: 'wst ticket does not match the wrapped session cookie',
      });
    }
  }

  return { findings, forwardedCookie: forwarded.join('; '), rawSid };
}

function blockedBody(findings) {
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

function corsHeaders(req) {
  const origin = header(req, 'origin');
  if (!origin || origin === 'null') return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}

function writeBlocked(socketOrRes, findings, asSocket, req) {
  const body = blockedBody(findings);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-WAF-Action': 'BLOCK',
    'X-WAF-WebACL': WEB_ACL_NAME,
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
    ...corsHeaders(req || { headers: {} }),
  };
  if (asSocket) {
    const lines = ['HTTP/1.1 403 Forbidden'];
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
    socketOrRes.write(`${lines.join('\r\n')}\r\n\r\n${body}`);
    socketOrRes.destroy();
    return;
  }
  socketOrRes.writeHead(403, headers);
  socketOrRes.end(body);
}

function wrapSetCookieLine(line) {
  const segs = String(line).split(';');
  const pair = segs[0];
  const eq = pair.indexOf('=');
  if (eq <= 0) return [line];
  const name = pair.slice(0, eq).trim();
  let value = pair.slice(eq + 1);
  const attrs = segs.slice(1);
  if (name !== 'sid') return [line];
  let raw = value;
  try {
    raw = decodeURIComponent(value);
  } catch {
    raw = value;
  }
  const wrapped = hmacWrap(name, raw);
  if (!/httponly/i.test(attrs.join(';'))) attrs.push(' HttpOnly');
  if (!/samesite/i.test(attrs.join(';'))) attrs.push(' SameSite=Strict');
  const ticket = ticketForSid(raw);
  return [
    [`${name}=${wrapped}`, ...attrs].join(';'),
    `wst=${ticket}; Path=/; SameSite=Strict`,
  ];
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
    const { findings, forwardedCookie } = evaluateWaf(req);
    if (findings.length > 0) {
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '));
      writeBlocked(res, findings, false, req);
      return;
    }

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
          outHeaders['set-cookie'] = list.flatMap(wrapSetCookieLine);
        }
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

server.on('upgrade', (req, socket, head) => {
  socket.on('error', () => {});
  const { findings, forwardedCookie } = evaluateWaf(req);
  if (findings.length > 0) {
    console.log('[waf-proxy] BLOCK upgrade', findings.map((f) => f.rule).join(', '));
    writeBlocked(socket, findings, true, req);
    return;
  }

  const upstream = net.connect(UPSTREAM_PORT, UPSTREAM_HOST, () => {
    const skip = new Set(['host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'origin', 'cookie']);
    const lines = [`${req.method} ${req.url} HTTP/1.1`, `Host: ${UPSTREAM_HOST}:${UPSTREAM_PORT}`];
    for (const [k, v] of Object.entries(req.headers)) {
      if (skip.has(k.toLowerCase())) continue;
      const val = Array.isArray(v) ? v.join(', ') : v;
      lines.push(`${k}: ${val}`);
    }
    lines.push(`Origin: http://127.0.0.1:${UPSTREAM_PORT}`);
    if (forwardedCookie) lines.push(`Cookie: ${forwardedCookie}`);
    lines.push('Connection: Upgrade');
    lines.push('Upgrade: websocket');
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('close', () => upstream.destroy());
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[waf-proxy] VIP on ${PORT} → ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log('[waf-proxy] Origin pin + wst ticket + HSTS');
});
