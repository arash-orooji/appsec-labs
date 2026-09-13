'use strict';

const dgram = require('dgram');
const net = require('net');

const ATTACKER_A = '203.0.113.50';
const LOOPBACK = '127.0.0.1';
const UNSPEC = '0.0.0.0';

const TYPE_A = 1;
const TYPE_CNAME = 5;
const TYPE_AAAA = 28;
const CLASS_IN = 1;

function fqdn(name) {
  return String(name || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
}

function encodeName(name) {
  const labels = fqdn(name).split('.').filter(Boolean);
  const parts = [];
  for (const label of labels) {
    const buf = Buffer.from(label, 'ascii');
    if (buf.length > 63) throw new Error('label too long');
    parts.push(Buffer.from([buf.length]));
    parts.push(buf);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function decodeName(buf, offset) {
  let pos = offset;
  const labels = [];
  let jumped = false;
  let end = offset;
  let hops = 0;
  while (hops++ < 16) {
    if (pos >= buf.length) throw new Error('truncated name');
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) end = pos + 1;
      return { name: labels.join('.'), end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error('truncated pointer');
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) end = pos + 2;
      jumped = true;
      pos = ptr;
      continue;
    }
    pos += 1;
    if (pos + len > buf.length) throw new Error('truncated label');
    labels.push(buf.slice(pos, pos + len).toString('ascii').toLowerCase());
    pos += len;
  }
  throw new Error('name loop');
}

function ipToBuf(ip) {
  return Buffer.from(ip.split('.').map((o) => Number(o)));
}

function isRfc1918(ip) {
  const [a, b] = ip.split('.').map(Number);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isLoopback(ip) {
  return ip.split('.')[0] === '127';
}

function isUnspecified(ip) {
  return ip === '0.0.0.0';
}

function cnameIsLocalhost(target) {
  return fqdn(target) === 'localhost';
}

function cnameIsInternal(target) {
  return fqdn(target).endsWith('.local') || fqdn(target) === 'local';
}

function encodeRr(name, type, ttl, rdata) {
  return Buffer.concat([
    encodeName(name),
    Buffer.from([(type >> 8) & 0xff, type & 0xff, 0, CLASS_IN]),
    Buffer.from([
      (ttl >>> 24) & 0xff,
      (ttl >>> 16) & 0xff,
      (ttl >>> 8) & 0xff,
      ttl & 0xff,
    ]),
    Buffer.from([(rdata.length >> 8) & 0xff, rdata.length & 0xff]),
    rdata,
  ]);
}

function parseQuestion(buf) {
  if (buf.length < 12) throw new Error('short header');
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  if (qd < 1) throw new Error('no question');
  const q = decodeName(buf, 12);
  if (q.end + 4 > buf.length) throw new Error('short question');
  const qtype = buf.readUInt16BE(q.end);
  const qclass = buf.readUInt16BE(q.end + 2);
  return { id, flags, qname: q.name, qtype, qclass, qend: q.end + 4 };
}

function parseRr(buf, offset) {
  const name = decodeName(buf, offset);
  let pos = name.end;
  if (pos + 10 > buf.length) throw new Error('short rr');
  const type = buf.readUInt16BE(pos);
  const cls = buf.readUInt16BE(pos + 2);
  const ttl = buf.readUInt32BE(pos + 4);
  const rdlen = buf.readUInt16BE(pos + 8);
  pos += 10;
  if (pos + rdlen > buf.length) throw new Error('short rdata');
  const rdata = buf.slice(pos, pos + rdlen);
  const rr = { name: name.name, type, class: cls, ttl };
  if (type === TYPE_A && rdlen === 4) {
    rr.ip = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
  } else if (type === TYPE_CNAME) {
    rr.cname = decodeName(buf, pos).name;
  }
  return { rr, end: pos + rdlen };
}

function parseResponse(buf) {
  const query = parseQuestion(buf);
  const ancount = buf.readUInt16BE(6);
  let pos = query.qend;
  const answers = [];
  for (let i = 0; i < ancount; i += 1) {
    const parsed = parseRr(buf, pos);
    answers.push(parsed.rr);
    pos = parsed.end;
  }
  return {
    id: query.id,
    flags: buf.readUInt16BE(2),
    qname: query.qname,
    qtype: query.qtype,
    answers,
  };
}

function encodeQuery(qname, qtype = TYPE_A, id = 1) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([
    header,
    encodeName(qname),
    Buffer.from([(qtype >> 8) & 0xff, qtype & 0xff, 0, CLASS_IN]),
  ]);
}

function queryUdp(port, qname, qtype = TYPE_A, host = '127.0.0.1', timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const dgram = require('dgram');
    const sock = dgram.createSocket('udp4');
    const id = Math.floor(Math.random() * 65535);
    const payload = encodeQuery(qname, qtype, id);
    const timer = setTimeout(() => {
      sock.close();
      reject(new Error(`dns timeout ${qname} @${host}:${port}`));
    }, timeoutMs);
    sock.once('error', (err) => {
      clearTimeout(timer);
      try {
        sock.close();
      } catch {
        /* ignore */
      }
      reject(err);
    });
    sock.on('message', (msg) => {
      clearTimeout(timer);
      sock.close();
      try {
        resolve(parseResponse(msg));
      } catch (err) {
        reject(err);
      }
    });
    sock.send(payload, port, host);
  });
}

class RebindZone {
  constructor() {
    this.hits = new Map();
    this.firstHits = 1;
    this.records = {
      'classic.rebind.lab': { kind: 'a-flip', first: ATTACKER_A, next: LOOPBACK },
      'zero.rebind.lab': { kind: 'a-flip', first: ATTACKER_A, next: UNSPEC },
      'cname-int.rebind.lab': { kind: 'cname-flip', first: ATTACKER_A, cname: 'target.local' },
      'cname-localhost.rebind.lab': { kind: 'cname-flip', first: ATTACKER_A, cname: 'localhost' },
      'target.local': { kind: 'static-a', ip: LOOPBACK },
      localhost: { kind: 'static-a', ip: LOOPBACK },
    };
  }

  reset() {
    this.hits.clear();
  }

  bump(name) {
    const key = fqdn(name);
    const n = (this.hits.get(key) || 0) + 1;
    this.hits.set(key, n);
    return n;
  }

  snapshot() {
    return {
      firstHits: this.firstHits,
      hits: Object.fromEntries(this.hits),
    };
  }

  answersFor(qname, qtype) {
    const name = fqdn(qname);
    const rec = this.records[name];
    if (!rec) return [];
    if (qtype !== TYPE_A && qtype !== TYPE_CNAME && qtype !== 255) return [];

    if (rec.kind === 'static-a') {
      if (qtype === TYPE_CNAME) return [];
      return [{ type: TYPE_A, ttl: 1, ip: rec.ip }];
    }

    const hit = this.bump(name);
    if (hit <= this.firstHits) {
      if (qtype === TYPE_CNAME) return [];
      return [{ type: TYPE_A, ttl: 1, ip: rec.first }];
    }

    if (rec.kind === 'a-flip') {
      if (qtype === TYPE_CNAME) return [];
      return [{ type: TYPE_A, ttl: 0, ip: rec.next }];
    }

    return [{ type: TYPE_CNAME, ttl: 0, cname: rec.cname }];
  }
}

function filterAnswers(answers, mode) {
  if (mode === 'raw') return answers;
  return answers.filter((rr) => {
    if (rr.type === TYPE_A) {
      if (isRfc1918(rr.ip)) return false;
      if (isLoopback(rr.ip)) return false;
      if (mode === 'strict' && isUnspecified(rr.ip)) return false;
      return true;
    }
    if (rr.type === TYPE_CNAME) {
      if (mode === 'strict' && (cnameIsLocalhost(rr.cname) || cnameIsInternal(rr.cname))) {
        return false;
      }
      return true;
    }
    return false;
  });
}

function buildResponse(query, answers) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(query.id, 0);
  let flags = 0x8000;
  if (query.flags & 0x0100) flags |= 0x0100;
  flags |= 0x0400;
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const question = Buffer.concat([
    encodeName(query.qname),
    Buffer.from([(query.qtype >> 8) & 0xff, query.qtype & 0xff, 0, CLASS_IN]),
  ]);

  const rrBufs = answers.map((rr) => {
    if (rr.type === TYPE_A) {
      return encodeRr(query.qname, TYPE_A, rr.ttl, ipToBuf(rr.ip));
    }
    return encodeRr(query.qname, TYPE_CNAME, rr.ttl, encodeName(rr.cname));
  });

  return Buffer.concat([header, question, ...rrBufs]);
}

function handleQuery(zone, mode, msg) {
  try {
    const query = parseQuestion(msg);
    if (query.qclass !== CLASS_IN && query.qclass !== 255) {
      return buildResponse(query, []);
    }
    const raw = zone.answersFor(query.qname, query.qtype);
    const filtered = filterAnswers(raw, mode);
    return buildResponse(query, filtered);
  } catch {
    return null;
  }
}

function startUdp(port, onMsg) {
  const sock = dgram.createSocket('udp4');
  sock.on('message', onMsg);
  return new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.bind(port, '0.0.0.0', () => resolve(sock));
  });
}

function startTcp(port, onPayload) {
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (buf.length < 2 + len) break;
        const msg = buf.slice(2, 2 + len);
        buf = buf.slice(2 + len);
        const resp = onPayload(msg);
        if (resp) {
          const out = Buffer.alloc(2 + resp.length);
          out.writeUInt16BE(resp.length, 0);
          resp.copy(out, 2);
          socket.write(out);
        }
      }
    });
    socket.on('error', () => socket.destroy());
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', () => resolve(server));
  });
}

async function listenDns({ port, zone, mode }) {
  const reply = (msg) => handleQuery(zone, mode, msg);
  const udp = await startUdp(port, (msg, rinfo) => {
    const resp = reply(msg);
    if (resp) udp.send(resp, rinfo.port, rinfo.address);
  });
  const tcp = await startTcp(port, reply);
  return { udp, tcp, port, mode };
}

module.exports = {
  ATTACKER_A,
  LOOPBACK,
  UNSPEC,
  TYPE_A,
  TYPE_AAAA,
  TYPE_CNAME,
  RebindZone,
  filterAnswers,
  handleQuery,
  listenDns,
  fqdn,
  parseQuestion,
  parseResponse,
  encodeQuery,
  encodeName,
  queryUdp,
};
