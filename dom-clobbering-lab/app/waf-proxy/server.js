/**
 * WAF VIP for HarborNotes.
 *
 * DOM clobbering rides in HTML the sanitizer considers safe. The VIP
 * rejects named-element gadgets that overwrite first-party config
 * (id/name of known globals, nested SESSION forms, getElementById smash).
 */
const http = require('http');

const PORT = Number(process.env.PORT || 8780);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3700);
const WEB_ACL_NAME = process.env.WEB_ACL_NAME || 'DOM-Clobbering-Protection';

function header(req, name) {
  const key = Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? String(req.headers[key]) : '';
}

function haystack(req, body) {
  const raw = String(body || '');
  let extra = '';
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.widget === 'string') extra += `\n${parsed.widget}`;
  } catch {
    /* not JSON */
  }
  try {
    extra += `\n${decodeURIComponent(raw.replace(/\+/g, ' '))}`;
  } catch {
    /* ignore */
  }
  return `${req.url || ''}\n${raw}\n${extra}`;
}

function evaluateWaf(req, body) {
  const text = haystack(req, body);
  const findings = [];

  if (/id\s*=\s*["']?IS_PREMIUM\b/i.test(text)) {
    findings.push({
      rule: 'Block-Clobbered-Window-Id',
      reason: 'id=IS_PREMIUM would clobber window.IS_PREMIUM',
    });
  }
  if (/id\s*=\s*["']?ASSET_HOST\b/i.test(text)) {
    findings.push({
      rule: 'Block-Anchor-ToString-Gadget',
      reason: 'id=ASSET_HOST (anchor toString / CDN hijack)',
    });
  }
  if (/id\s*=\s*["']?SESSION\b/i.test(text) && /name\s*=\s*["']?priv\b/i.test(text)) {
    findings.push({
      rule: 'Block-Nested-Form-Clobber',
      reason: 'form#SESSION + input[name=priv] nested named-property clobber',
    });
  }
  if (/id\s*=\s*["']?API\b/i.test(text) && /name\s*=\s*["']?endpoint\b/i.test(text)) {
    findings.push({
      rule: 'Block-HtmlCollection-Clobber',
      reason: 'duplicate id=API + name=endpoint HTMLCollection gadget',
    });
  }
  if (/name\s*=\s*["']?getElementById\b/i.test(text)) {
    findings.push({
      rule: 'Block-GetElementById-Smash',
      reason: 'name=getElementById shadows document.getElementById',
    });
  }
  if (/(id|name)\s*=\s*["']?checkout\b/i.test(text) && /action\s*=/i.test(text)) {
    findings.push({
      rule: 'Block-Form-Action-Clobber',
      reason: 'named checkout form with action URL reflection',
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
        'Access-Control-Allow-Credentials': 'true',
      });
      res.end(json);
      return;
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
});
