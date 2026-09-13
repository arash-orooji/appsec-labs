/**
 * WAF gate for the OAuth lab (HarborNotes).
 *
 *  - Bind implicit POST /authenticate email to IdP /oauth/me
 *  - Require state= on /oauth-linking (CSRF)
 *  - Drop redirect_uri traversal and open redirects
 *  - Single-use authorization codes on /oauth-callback
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 9080);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 4000);
const IDP_HOST = process.env.IDP_HOST || '127.0.0.1';
const IDP_PORT = Number(process.env.IDP_PORT || 4098);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'OAuth-Misconfig-Protection';

const usedCodes = new Set();

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function parsedUrl(rawUrl) {
  try {
    return new URL(rawUrl || '/', 'http://waf.local');
  } catch {
    return new URL('/', 'http://waf.local');
  }
}

function idpJson(path, extraHeaders = {}) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: IDP_HOST,
        port: IDP_PORT,
        path,
        method: 'GET',
        headers: { Connection: 'close', ...extraHeaders },
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on('error', () => resolve(null));
    req.setTimeout(4000, () => req.destroy());
    req.end();
  });
}

function idpMe(token) {
  return idpJson('/oauth/me', { Authorization: `Bearer ${token}` });
}

async function evaluateWaf(req, bodyBuf) {
  const findings = [];
  const raw = String(req.url || '/');
  const decoded = decodeURIComponent(raw);
  const url = parsedUrl(raw);
  const path = url.pathname;

  if (raw.includes('..') || decoded.includes('..') || /%2e%2e/i.test(raw)) {
    findings.push({
      rule: 'Block-Redirect-Uri-Traversal',
      reason: 'URI contains path traversal used to move OAuth tokens off /oauth-callback',
    });
  }

  if (path.startsWith('/oauth-linking') && !url.searchParams.get('state')) {
    findings.push({
      rule: 'Block-OAuth-Linking-CSRF',
      reason: '/oauth-linking missing state= (forced OAuth profile linking)',
    });
  }

  if (path === '/post/next' || path.startsWith('/post/next')) {
    const dest = url.searchParams.get('path') || '';
    if (/^https?:/i.test(dest) || dest.startsWith('//')) {
      findings.push({
        rule: 'Block-Open-Redirect',
        reason: '/post/next open redirect to an absolute URL (OAuth token leak)',
      });
    }
  }

  if (path.includes('comment-form') && (raw.includes('access_token') || decoded.includes('access_token'))) {
    findings.push({
      rule: 'Block-Proxy-Page-Token',
      reason: 'comment-form used as an OAuth proxy page',
    });
  }

  if (path.startsWith('/oauth-callback')) {
    const code = url.searchParams.get('code');
    if (code && usedCodes.has(code)) {
      findings.push({
        rule: 'Block-Authorization-Code-Reuse',
        reason: 'authorization code already used (RFC 6749)',
      });
    }
    if (code) {
      const info = await idpJson(`/oauth/code-info?code=${encodeURIComponent(code)}`);
      const registered = `http://127.0.0.1:${UPSTREAM_PORT}/oauth-callback`;
      if (info && info.redirectUri && info.redirectUri !== registered && info.redirectUri !== `${registered}`) {
        findings.push({
          rule: 'Block-Stolen-Redirect-Uri-Code',
          reason: `authorization code was issued for ${info.redirectUri}, not the registered callback`,
        });
      }
    }
  }

  if (req.method === 'POST' && path === '/authenticate') {
    let json = {};
    try {
      json = JSON.parse(bodyBuf.toString('utf8') || '{}');
    } catch {
      json = {};
    }
    if (json.token && json.email) {
      const me = await idpMe(json.token);
      const claimed = String(json.email).toLowerCase();
      const actual = me && me.email ? String(me.email).toLowerCase() : '';
      if (!me || claimed !== actual) {
        findings.push({
          rule: 'Block-Implicit-Email-Swap',
          reason: `POST /authenticate email ${claimed} does not match token subject ${actual || '(unknown)'}`,
        });
      }
    }
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
    const findings = await evaluateWaf(req, bodyBuf);
    if (findings.length > 0) {
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '), req.url);
      const blocked = blockedResponse(findings);
      res.writeHead(blocked.statusCode, blocked.headers);
      res.end(blocked.body);
      return;
    }

    const url = parsedUrl(req.url);
    if (url.pathname.startsWith('/oauth-callback') && url.searchParams.get('code')) {
      usedCodes.add(url.searchParams.get('code'));
    }

    console.log('[waf-proxy] ALLOW', req.method, req.url);
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
  console.log(`[waf-proxy] listening on ${PORT}, upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}, idp ${IDP_HOST}:${IDP_PORT}`);
});
