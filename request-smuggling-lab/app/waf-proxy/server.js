/**
 * Local WAF gate — applies the same detection logic as the LocalStack WebACL rules.
 * Real AWS WAF would enforce these when the WebACL is associated with an ALB/CloudFront.
 * LocalStack stores the ACL; this proxy demonstrates the block behavior on traffic.
 */
const net = require('net');

const PORT = Number(process.env.PORT || 8180);
const UPSTREAM_HOST = process.env.UPSTREAM_HOST || 'frontend';
const UPSTREAM_PORT = Number(process.env.UPSTREAM_PORT || 3100);

function headerValues(rawHead, name) {
  const values = [];
  const re = new RegExp(`^${name}\\s*:\\s*(.*)$`, 'gim');
  let m;
  while ((m = re.exec(rawHead)) !== null) {
    values.push(m[1].trim());
  }
  return values;
}

function evaluateWaf(rawHead) {
  const findings = [];

  const teValues = headerValues(rawHead, 'Transfer-Encoding');
  const clValues = headerValues(rawHead, 'Content-Length');

  // Rule 1: both Content-Length and Transfer-Encoding (classic smuggling signal)
  if (teValues.length > 0 && clValues.length > 0) {
    findings.push({
      rule: 'Block-CL-TE-Smuggling',
      reason: 'Request has both Content-Length and Transfer-Encoding headers',
    });
  }

  // Rule 2: obfuscated / multiple Transfer-Encoding
  for (const te of teValues) {
    const normalized = te.toLowerCase();
    if (
      normalized.includes(',') ||
      normalized.includes('\t') ||
      normalized.includes(' ') ||
      /chunked[^a-z]|[^a-z]chunked|xchunked|chunked\r/i.test(te) ||
      normalized === 'identity,chunked' ||
      normalized.includes('identity')
    ) {
      findings.push({
        rule: 'Block-TE-Obfuscation',
        reason: `Obfuscated Transfer-Encoding: ${te}`,
      });
    }
  }
  if (teValues.length > 1) {
    findings.push({
      rule: 'Block-TE-Obfuscation',
      reason: 'Multiple Transfer-Encoding headers',
    });
  }

  // Rule 3: duplicate / malformed Content-Length
  if (clValues.length > 1) {
    findings.push({
      rule: 'Block-Malformed-Content-Length',
      reason: `Multiple Content-Length headers: ${clValues.join(' | ')}`,
    });
  }
  for (const cl of clValues) {
    if (cl.includes(',') || /\s/.test(cl)) {
      findings.push({
        rule: 'Block-Malformed-Content-Length',
        reason: `Malformed Content-Length: ${cl}`,
      });
    }
  }

  // Rule 4: Transfer-Encoding present but not exactly "chunked"
  for (const te of teValues) {
    if (te.toLowerCase() !== 'chunked') {
      findings.push({
        rule: 'Block-TE-Obfuscation',
        reason: `Non-standard Transfer-Encoding value: ${te}`,
      });
    }
  }

  return findings;
}

function blockedResponse(findings) {
  const body = JSON.stringify(
    {
      message: 'Blocked by AWS WAF (lab simulation)',
      webAcl: 'Request-Smuggling-Protection',
      matches: findings,
    },
    null,
    2
  );
  return (
    `HTTP/1.1 403 Forbidden\r\n` +
    `Content-Type: application/json\r\n` +
    `X-WAF-Action: BLOCK\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `Connection: close\r\n\r\n` +
    body
  );
}

const server = net.createServer((socket) => {
  let buffer = Buffer.alloc(0);
  let decided = false;

  socket.on('data', (chunk) => {
    if (decided) return;
    buffer = Buffer.concat([buffer, chunk]);
    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    decided = true;
    const rawHead = buffer.slice(0, headerEnd).toString();
    const findings = evaluateWaf(rawHead);

    if (findings.length > 0) {
      console.log('[waf-proxy] BLOCK', findings.map((f) => f.rule).join(', '));
      socket.write(blockedResponse(findings));
      socket.end();
      return;
    }

    console.log('[waf-proxy] ALLOW → upstream');
    const upstream = net.createConnection({ host: UPSTREAM_HOST, port: UPSTREAM_PORT }, () => {
      upstream.write(buffer);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    upstream.on('error', (err) => {
      const msg = `Upstream error: ${err.message}`;
      socket.write(
        `HTTP/1.1 502 Bad Gateway\r\nContent-Length: ${msg.length}\r\nConnection: close\r\n\r\n${msg}`
      );
      socket.end();
    });
  });

  socket.on('error', () => {});
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[waf-proxy] listening on ${PORT}, upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
});
