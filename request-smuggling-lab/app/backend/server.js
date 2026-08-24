/**
 * Backend origin — prefers Transfer-Encoding: chunked when both CL and TE exist.
 * This mismatch with the frontend (CL preference) enables CL.TE smuggling.
 */
const net = require('net');

const PORT = Number(process.env.PORT || 3001);
const SECRET = process.env.ADMIN_SECRET || 'FLAG{request-smuggling-success}';

function getHeader(headers, name) {
  const key = Object.keys(headers).find((h) => h.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

function parseHeaders(raw) {
  const lines = raw.split('\r\n');
  const [method, path, version] = lines[0].split(' ');
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    const name = lines[i].slice(0, idx).trim();
    const value = lines[i].slice(idx + 1).trim();
    // Keep first value only for lookup, but track duplicates
    if (!headers[name]) headers[name] = value;
    else headers[name] = `${headers[name]}, ${value}`;
  }
  return { method, path, version, headers };
}

function decodeChunked(buf) {
  let offset = 0;
  let body = Buffer.alloc(0);
  while (offset < buf.length) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd === -1) break;
    const sizeLine = buf.slice(offset, lineEnd).toString();
    const size = parseInt(sizeLine.split(';')[0], 16);
    if (Number.isNaN(size)) break;
    offset = lineEnd + 2;
    if (size === 0) {
      // Skip trailer / final CRLF
      const rest = buf.slice(offset);
      const end = rest.indexOf('\r\n');
      const consumed = end === -1 ? buf.length : offset + end + 2;
      return { body, consumed, leftover: buf.slice(consumed) };
    }
    body = Buffer.concat([body, buf.slice(offset, offset + size)]);
    offset += size + 2; // chunk data + CRLF
  }
  return { body, consumed: buf.length, leftover: Buffer.alloc(0) };
}

function readBody(headers, rawBody) {
  const te = getHeader(headers, 'transfer-encoding');
  const cl = getHeader(headers, 'content-length');

  // Backend prefers TE when both are present (TE side of CL.TE)
  if (te && /chunked/i.test(te)) {
    return decodeChunked(rawBody);
  }
  if (cl !== undefined) {
    const length = parseInt(cl, 10);
    return {
      body: rawBody.slice(0, length),
      consumed: length,
      leftover: rawBody.slice(length),
    };
  }
  return { body: Buffer.alloc(0), consumed: 0, leftover: rawBody };
}

function htmlPage(title, body) {
  return (
    `<!DOCTYPE html><html><head><title>${title}</title></head>` +
    `<body style="font-family:system-ui;max-width:720px;margin:2rem auto">` +
    `<h1>${title}</h1>${body}</body></html>`
  );
}

function handleRequest(req, bodyBuf) {
  const path = (req.path || '/').split('?')[0];
  console.log(`[backend] ${req.method} ${path} te=${getHeader(req.headers, 'transfer-encoding') || '-'} cl=${getHeader(req.headers, 'content-length') || '-'}`);

  if (path === '/admin') {
    // No auth on purpose — the lesson is reaching /admin via desync
    return {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: htmlPage(
        'Admin Panel',
        `<p>Smuggled request reached the protected endpoint.</p>` +
          `<p><strong>Secret:</strong> <code>${SECRET}</code></p>` +
          `<p>Body received: <code>${bodyBuf.toString().slice(0, 200)}</code></p>`
      ),
    };
  }

  if (path === '/health') {
    return {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true, role: 'backend' }),
    };
  }

  return {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
    body: htmlPage(
      'Public Backend',
      `<p>This is the public origin. Admin is at <code>/admin</code> (not linked).</p>` +
        `<p>Method: ${req.method}</p>` +
        `<p>Path: ${path}</p>` +
        `<p>Body length: ${bodyBuf.length}</p>`
    ),
  };
}

function writeResponse(socket, res, close = true) {
  const body = Buffer.from(res.body);
  const lines = [
    `HTTP/1.1 ${res.status} ${res.status === 200 ? 'OK' : 'Error'}`,
    `Content-Length: ${body.length}`,
    close ? 'Connection: close' : 'Connection: keep-alive',
  ];
  for (const [k, v] of Object.entries(res.headers || {})) {
    lines.push(`${k}: ${v}`);
  }
  socket.write(lines.join('\r\n') + '\r\n\r\n');
  socket.write(body);
  if (close) socket.end();
}

function processBuffer(socket, state) {
  while (true) {
    const data = state.buffer;
    const headerEnd = data.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const headerRaw = data.slice(0, headerEnd).toString();
    const req = parseHeaders(headerRaw);
    const afterHeaders = data.slice(headerEnd + 4);
    const { body, consumed, leftover } = readBody(req.headers, afterHeaders);

    // Need more body bytes?
    const te = getHeader(req.headers, 'transfer-encoding');
    const cl = getHeader(req.headers, 'content-length');
    if (te && /chunked/i.test(te)) {
      // If no terminating 0-chunk yet, wait
      if (!/\r\n0\r\n/i.test(afterHeaders.toString()) && !/^0\r\n/i.test(afterHeaders.toString())) {
        return;
      }
    } else if (cl !== undefined) {
      const length = parseInt(cl, 10);
      if (afterHeaders.length < length) return;
    }

    const response = handleRequest(req, body);
    const close = (getHeader(req.headers, 'connection') || '').toLowerCase() === 'close';
    writeResponse(socket, response, close || leftover.length === 0);

    state.buffer = leftover.length ? leftover : afterHeaders.slice(consumed);
    if (state.buffer.length === 0) return;
    // Loop to process smuggled / pipelined request in leftover
  }
}

const server = net.createServer((socket) => {
  const state = { buffer: Buffer.alloc(0) };
  socket.on('data', (chunk) => {
    state.buffer = Buffer.concat([state.buffer, chunk]);
    try {
      processBuffer(socket, state);
    } catch (err) {
      console.error('[backend] parse error', err.message);
      socket.write('HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request');
    }
  });
  socket.on('error', () => {});
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[backend] listening on ${PORT} (prefers Transfer-Encoding)`);
});
