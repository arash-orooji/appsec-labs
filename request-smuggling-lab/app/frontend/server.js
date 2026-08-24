/**
 * Vulnerable reverse proxy — prefers Content-Length when both CL and TE exist.
 * Combined with the TE-preferring backend, this creates a classic CL.TE desync.
 */
const net = require('net');

const PORT = Number(process.env.PORT || 3100);
const BACKEND_HOST = process.env.BACKEND_HOST || 'backend';
const BACKEND_PORT = Number(process.env.BACKEND_PORT || 3001);

function getHeader(headers, name) {
  const key = Object.keys(headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

function parseRequestHead(raw) {
  const lines = raw.split('\r\n');
  const [method, path, version] = lines[0].split(' ');
  const headers = {};
  const headerOrder = [];
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    const name = lines[i].slice(0, idx).trim();
    const value = lines[i].slice(idx + 1).trim();
    headerOrder.push([name, value]);
    if (!headers[name]) headers[name] = value;
    else headers[`${name}#${Object.keys(headers).length}`] = value;
  }
  return { method, path, version, headers, headerOrder, rawHead: raw };
}

function frontendBodyLength(headers, rawBody) {
  const te = getHeader(headers, 'transfer-encoding');
  const cl = getHeader(headers, 'content-length');

  // VULNERABLE: frontend trusts Content-Length even when TE is present (CL.TE)
  if (cl !== undefined) {
    const length = parseInt(cl, 10);
    return {
      body: rawBody.slice(0, length),
      consumed: Number.isNaN(length) ? 0 : length,
      mode: 'content-length',
    };
  }

  if (te && /chunked/i.test(te)) {
    // TE.CL path when only TE is set — naive chunk decode
    let offset = 0;
    let body = Buffer.alloc(0);
    while (offset < rawBody.length) {
      const lineEnd = rawBody.indexOf('\r\n', offset);
      if (lineEnd === -1) return { needMore: true };
      const size = parseInt(rawBody.slice(offset, lineEnd).toString().split(';')[0], 16);
      offset = lineEnd + 2;
      if (size === 0) {
        const trail = rawBody.indexOf('\r\n', offset);
        const consumed = trail === -1 ? rawBody.length : trail + 2;
        return { body, consumed, mode: 'chunked' };
      }
      if (offset + size + 2 > rawBody.length) return { needMore: true };
      body = Buffer.concat([body, rawBody.slice(offset, offset + size)]);
      offset += size + 2;
    }
    return { needMore: true };
  }

  return { body: Buffer.alloc(0), consumed: 0, mode: 'empty' };
}

function buildForwardRequest(req, body) {
  // Strip hop-by-hop; keep CL/TE as the frontend understood them (desync bait)
  const lines = [`${req.method} ${req.path} HTTP/1.1`];
  let sawHost = false;
  for (const [name, value] of req.headerOrder) {
    const lower = name.toLowerCase();
    if (lower === 'connection' || lower === 'proxy-connection' || lower === 'keep-alive') continue;
    if (lower === 'host') {
      lines.push(`Host: ${BACKEND_HOST}`);
      sawHost = true;
      continue;
    }
    lines.push(`${name}: ${value}`);
  }
  if (!sawHost) lines.push(`Host: ${BACKEND_HOST}`);
  lines.push('Connection: close');
  return Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n'), body]);
}

function proxyToBackend(payload) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    const client = net.createConnection({ host: BACKEND_HOST, port: BACKEND_PORT }, () => {
      client.write(payload);
    });
    const chunks = [];
    let buffer = Buffer.alloc(0);
    let headerDone = false;
    let expected = null;

    client.on('data', (c) => {
      chunks.push(c);
      buffer = Buffer.concat([buffer, c]);
      if (!headerDone) {
        const idx = buffer.indexOf('\r\n\r\n');
        if (idx === -1) return;
        headerDone = true;
        const head = buffer.slice(0, idx).toString();
        const cl = /content-length:\s*(\d+)/i.exec(head);
        expected = cl ? idx + 4 + parseInt(cl[1], 10) : null;
      }
      if (expected !== null && buffer.length >= expected) {
        client.end();
        done(resolve, Buffer.concat(chunks).slice(0, expected));
      }
    });
    client.on('end', () => done(resolve, Buffer.concat(chunks)));
    client.on('error', (err) => done(reject, err));
    client.setTimeout(5000, () => {
      client.destroy();
      done(reject, new Error('backend timeout'));
    });
  });
}

function landingPage() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>HTTP Request Smuggling Lab</title>
  <style>
    body { font-family: Georgia, serif; max-width: 800px; margin: 2rem auto; line-height: 1.5; color: #1a1a1a; }
    code, pre { font-family: Consolas, monospace; background: #f3f3f0; padding: 0.15em 0.35em; }
    pre { padding: 1rem; overflow: auto; }
    .warn { border-left: 4px solid #b45309; padding-left: 1rem; background: #fffbeb; }
    a { color: #0f4c81; }
  </style>
</head>
<body>
  <h1>HTTP Request Smuggling Lab</h1>
  <p>Vulnerable CL.TE reverse proxy (Node.js) + TE-preferring backend.</p>
  <div class="warn">
    <p><strong>Direct app:</strong> <code>http://localhost:3100</code> — smuggling works.</p>
    <p><strong>WAF gate:</strong> <code>http://localhost:8180</code> — AWS WAF-style rules block CL+TE.</p>
  </div>
  <h2>Endpoints</h2>
  <ul>
    <li><a href="/">/</a> — public page (this)</li>
    <li><code>/admin</code> — protected (reach via smuggling)</li>
    <li><a href="/health">/health</a> — health check</li>
  </ul>
  <h2>CL.TE PoC idea</h2>
  <pre>POST / HTTP/1.1
Host: localhost
Content-Length: 39
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X</pre>
  <p>Run <code>./exploit/clte-smuggle.sh</code> for a ready-made payload.</p>
</body>
</html>`;
}

const server = net.createServer((socket) => {
  let buffer = Buffer.alloc(0);

  socket.on('data', async (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    try {
      while (true) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;

        const headRaw = buffer.slice(0, headerEnd).toString();
        const req = parseRequestHead(headRaw);
        const after = buffer.slice(headerEnd + 4);
        const parsed = frontendBodyLength(req.headers, after);
        if (parsed.needMore) return;

        const body = parsed.body || Buffer.alloc(0);
        const consumed = parsed.consumed || 0;

        console.log(
          `[frontend] ${req.method} ${req.path} mode=${parsed.mode} body=${body.length} leftover=${after.length - consumed}`
        );

        if (req.path === '/' && req.method === 'GET') {
          const page = Buffer.from(landingPage());
          socket.write(
            `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${page.length}\r\nConnection: close\r\n\r\n`
          );
          socket.write(page);
          socket.end();
          return;
        }

        // Forward what THIS proxy believes is one request.
        // Leftover bytes (smuggled) stay in the client buffer and become the next request
        // the proxy parses — demonstrating desync / smuggled follow-up.
        const forward = buildForwardRequest(req, body);
        let backendResp;
        try {
          backendResp = await proxyToBackend(forward);
        } catch (err) {
          const msg = Buffer.from(`Upstream error: ${err.message}`);
          socket.write(
            `HTTP/1.1 502 Bad Gateway\r\nContent-Length: ${msg.length}\r\nConnection: close\r\n\r\n`
          );
          socket.write(msg);
          socket.end();
          return;
        }

        socket.write(backendResp);

        buffer = after.slice(consumed);
        if (buffer.length === 0) {
          socket.end();
          return;
        }
        // Continue loop: leftover is treated as a new request (smuggled /admin)
        console.log(`[frontend] processing leftover (${buffer.length} bytes) as next request`);
      }
    } catch (err) {
      console.error('[frontend] error', err.message);
      socket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request');
      socket.end();
    }
  });

  socket.on('error', () => {});
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[frontend] vulnerable proxy on ${PORT} → ${BACKEND_HOST}:${BACKEND_PORT}`);
  console.log('[frontend] prefers Content-Length when CL + TE are both present');
});
