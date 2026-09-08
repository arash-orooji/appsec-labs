/**
 * WAF gate for the session-puzzling 2FA lab.
 *
 * Blocks backup-code retrieval while the client is in the password-ok /
 * 2FA-pending state (Cookie auth_step=pending_2fa), matching the WAF Classic
 * WebACL Session-Puzzling-2FA-Protection.
 */
const http = require('http');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8380);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3300);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'Session-Puzzling-2FA-Protection';

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

function evaluateWaf(req) {
  const findings = [];
  const path = pathnameOf(req.url).toLowerCase();
  const cookie = header(req, 'cookie');
  const pending = /(?:^|;\s*)auth_step=pending_2fa(?:;|$)/i.test(cookie) || cookie.includes('pending_2fa');
  const backupUri =
    path.includes('backup-codes') || path.includes('getbackupcodes') || path.includes('/backup_codes');

  if (backupUri && pending) {
    findings.push({
      rule: 'Block-Backup-Codes-Pending-2FA',
      reason:
        'URI requests backup codes while Cookie auth_step=pending_2fa (password ok, 2FA not done)',
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
  console.log('[waf-proxy] engine=AWS WAF Classic — blocks backup codes during pending 2FA');
});
