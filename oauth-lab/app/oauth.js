'use strict';

const crypto = require('crypto');

function rid(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

class OAuthStore {
  constructor() {
    this.codes = new Map();
    this.tokens = new Map();
  }

  reset() {
    this.codes.clear();
    this.tokens.clear();
  }

  issueToken(userId, clientId) {
    const accessToken = `atk_${rid(20)}`;
    this.tokens.set(accessToken, {
      userId,
      clientId,
      issuedAt: Date.now(),
    });
    return accessToken;
  }

  authorize({ userId, clientId, redirectUri, responseType }) {
    if (responseType === 'token') {
      return { accessToken: this.issueToken(userId, clientId), redirectUri };
    }
    const code = `code_${rid(16)}`;
    this.codes.set(code, {
      userId,
      clientId,
      redirectUri,
      used: false,
      useCount: 0,
    });
    return { code, redirectUri };
  }

  /**
   * RFC 6749: the client MUST NOT use the authorization code more than once.
   * HarborSocial ignores that (PAT "Authorization Code Rule Violation").
   */
  exchange(code) {
    const rec = this.codes.get(code);
    if (!rec) return null;
    rec.used = true;
    rec.useCount += 1;
    const accessToken = this.issueToken(rec.userId, rec.clientId);
    return { accessToken, userId: rec.userId, useCount: rec.useCount, redirectUri: rec.redirectUri };
  }

  lookupToken(accessToken) {
    return this.tokens.get(accessToken) || null;
  }

  snapshot() {
    return {
      codes: this.codes.size,
      tokens: this.tokens.size,
    };
  }
}

function buildRedirect({ redirectUri, responseType, code, accessToken, state }) {
  const url = new URL(redirectUri, 'http://127.0.0.1');
  if (responseType === 'token') {
    const hash = new URLSearchParams({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: '3600',
    });
    if (state) hash.set('state', state);
    return `${redirectUri}#${hash.toString()}`;
  }
  const sep = redirectUri.includes('?') ? '&' : '?';
  const qs = new URLSearchParams({ code });
  if (state) qs.set('state', state);
  return `${redirectUri}${sep}${qs.toString()}`;
}

/**
 * Vulnerable allowlist: string prefix of the registered callback.
 * `/oauth-callback/../post/next` still "starts with" the registered URI.
 * Also accepts any other absolute URL (account hijack via redirect_uri).
 */
function redirectPermitted(redirectUri, registeredPrefix) {
  const raw = String(redirectUri || '');
  if (!raw) return false;
  if (raw.startsWith(registeredPrefix)) return true;
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

module.exports = { OAuthStore, buildRedirect, redirectPermitted, rid };
