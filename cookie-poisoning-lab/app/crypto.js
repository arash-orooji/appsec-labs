/**
 * Cookie-crypto helpers for the HarborCart poisoning lab.
 * Used by the app and by exploit/workbench scripts.
 */
const crypto = require('crypto');

const HMAC_SECRET = process.env.HMAC_SECRET || 'harbor-hmac-gap-key';
const AES_KEY = Buffer.from(process.env.AES_KEY || 'f5-lab-aes-key!!'); // 16 bytes
const LEGACY_SECRET = process.env.LEGACY_SECRET || 'harbor!!'; // 8 bytes, prefix-MAC
const LEGACY_SECRET_LEN = Buffer.byteLength(LEGACY_SECRET);

function parseKv(raw, sep = '|') {
  const out = {};
  for (const part of String(raw || '').split(sep)) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

/* ---- Stage 3: HMAC covers only user=, not role= ---- */

function authzMac(user) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(`user=${user}`).digest('hex').slice(0, 32);
}

function makeAuthz(user, role) {
  return `user=${user}|role=${role}|mac=${authzMac(user)}`;
}

function parseAuthz(raw) {
  const p = parseKv(raw, '|');
  if (!p.user || !p.role || !p.mac) return { ok: false, reason: 'malformed' };
  if (p.mac !== authzMac(p.user)) return { ok: false, reason: 'bad mac', user: p.user, role: p.role };
  return { ok: true, user: p.user, role: p.role };
}

/* ---- Stage 4: AES-128-CBC, no MAC (bit-flippable) ---- */

const VAULT_PLAIN = 'uid=101&admin=0'; // 15 bytes, '0' at index 14

function encryptVault(plain = VAULT_PLAIN) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-128-cbc', AES_KEY, iv);
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}.${ct.toString('hex')}`;
}

function decryptVault(token) {
  const [ivHex, ctHex] = String(token || '').split('.');
  if (!ivHex || !ctHex) throw new Error('malformed vault cookie');
  const iv = Buffer.from(ivHex, 'hex');
  const ct = Buffer.from(ctHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', AES_KEY, iv);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  return parseKv(plain, '&');
}

function bitflipVaultAdmin(token) {
  const [ivHex, ctHex] = String(token || '').split('.');
  const iv = Buffer.from(ivHex, 'hex');
  // First-block bit flip: IV[14] ^= ('0' XOR '1') changes admin=0 → admin=1
  iv[14] ^= 0x01;
  return `${iv.toString('hex')}.${ctHex}`;
}

/* ---- Stage 5: MD5(secret || data) hash-length extension ---- */

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21,
  6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i += 1) MD5_K[i] = Math.floor(2 ** 32 * Math.abs(Math.sin(i + 1))) >>> 0;

function rol(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function md5Padding(msgLen) {
  const zeros = (56 - ((msgLen + 1) % 64) + 64) % 64;
  const pad = Buffer.alloc(1 + zeros + 8);
  pad[0] = 0x80;
  const bits = BigInt(msgLen) * 8n;
  pad.writeUInt32LE(Number(bits & 0xffffffffn), pad.length - 8);
  pad.writeUInt32LE(Number((bits >> 32n) & 0xffffffffn), pad.length - 4);
  return pad;
}

function md5Compress(state, block) {
  const M = new Uint32Array(16);
  for (let i = 0; i < 16; i += 1) M[i] = block.readUInt32LE(i * 4);
  let [a, b, c, d] = state;
  for (let i = 0; i < 64; i += 1) {
    let f;
    let g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    const tmp = d;
    d = c;
    c = b;
    b = (b + rol((a + f + MD5_K[i] + M[g]) >>> 0, MD5_S[i])) >>> 0;
    a = tmp;
  }
  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
}

function md5StateFromDigest(digest) {
  const b = Buffer.isBuffer(digest) ? digest : Buffer.from(digest, 'hex');
  return [b.readUInt32LE(0), b.readUInt32LE(4), b.readUInt32LE(8), b.readUInt32LE(12)];
}

function digestFromState(state) {
  const out = Buffer.alloc(16);
  out.writeUInt32LE(state[0], 0);
  out.writeUInt32LE(state[1], 4);
  out.writeUInt32LE(state[2], 8);
  out.writeUInt32LE(state[3], 12);
  return out;
}

function md5Hash(buf) {
  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const pad = md5Padding(buf.length);
  const all = Buffer.concat([buf, pad]);
  for (let i = 0; i < all.length; i += 64) md5Compress(state, all.subarray(i, i + 64));
  return digestFromState(state);
}

function md5Continue(digest, extra, lengthBeforeExtra) {
  const state = md5StateFromDigest(digest);
  const pad = md5Padding(lengthBeforeExtra + extra.length);
  const all = Buffer.concat([Buffer.from(extra), pad]);
  for (let i = 0; i < all.length; i += 64) md5Compress(state, all.subarray(i, i + 64));
  return digestFromState(state);
}

function legacySign(data) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return md5Hash(Buffer.concat([Buffer.from(LEGACY_SECRET), payload])).toString('hex');
}

function hashLengthExtend(originalData, originalSigHex, extra, secretLen = LEGACY_SECRET_LEN) {
  const glue = md5Padding(secretLen + Buffer.byteLength(originalData));
  const forgedData = Buffer.concat([Buffer.from(originalData), glue, Buffer.from(extra)]);
  const lengthBeforeExtra = secretLen + Buffer.byteLength(originalData) + glue.length;
  const forgedSig = md5Continue(originalSigHex, extra, lengthBeforeExtra).toString('hex');
  return {
    data: forgedData,
    dataB64: forgedData.toString('base64url'),
    sig: forgedSig,
    glueHex: glue.toString('hex'),
  };
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function b64urlDecode(str) {
  return Buffer.from(String(str), 'base64url');
}

module.exports = {
  HMAC_SECRET,
  AES_KEY,
  LEGACY_SECRET,
  LEGACY_SECRET_LEN,
  VAULT_PLAIN,
  parseKv,
  authzMac,
  makeAuthz,
  parseAuthz,
  encryptVault,
  decryptVault,
  bitflipVaultAdmin,
  md5Padding,
  md5Hash,
  legacySign,
  hashLengthExtend,
  b64urlEncode,
  b64urlDecode,
};
