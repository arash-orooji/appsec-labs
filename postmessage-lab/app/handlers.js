/**
 * HarborLink postMessage gadgets.
 *
 * Vulnerable handler trusts event.data and uses broken origin tests.
 * Secure handler pins an exact origin, allowlists ops, and refuses
 * string JSON / prototype-merge / navigation.
 */
const FLAGS = {
  noOrigin: 'FLAG{pm-no-origin}',
  wildcard: 'FLAG{pm-wildcard-send}',
  includes: 'FLAG{pm-origin-includes}',
  prefix: 'FLAG{pm-origin-prefix}',
  nullOrigin: 'FLAG{pm-null-origin}',
  suffix: 'FLAG{pm-origin-suffix}',
  proto: 'FLAG{pm-proto}',
  nav: 'FLAG{pm-open-url}',
  complete: 'FLAG{pm-complete}',
};

function unique(list) {
  return [...new Set(list.filter(Boolean))];
}

function parseData(raw) {
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return { raw };
    }
  }
  return raw;
}

/**
 * Intentionally unsafe merge: a `__proto__` key writes onto Object.prototype.
 * Used only for the proto-pollution stage; cleaned up afterwards.
 */
function unsafeDeepMerge(target, src) {
  if (!src || typeof src !== 'object') return target;
  for (const key of Object.keys(src)) {
    const val = src[key];
    if (key === '__proto__' && val && typeof val === 'object') {
      unsafeDeepMerge(Object.prototype, val);
      continue;
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      unsafeDeepMerge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

function cleanupPollution() {
  try {
    if (Object.prototype.hasOwnProperty('admin')) {
      delete Object.prototype.admin;
    }
  } catch {
    /* ignore */
  }
}

function handleVulnerable(ev, ctx) {
  const flags = [];
  const replies = [];
  const origin = ev.origin == null ? '' : String(ev.origin);
  const data = parseData(ev.data);
  if (!data || typeof data !== 'object') return { flags, replies };

  if (data.op === 'banner') {
    if (ctx.setHtml) ctx.setHtml(String(data.html || ''));
    if (origin !== ctx.selfOrigin) flags.push(FLAGS.noOrigin);
  }

  if (data.op === 'hello') {
    replies.push({
      data: { op: 'session', token: ctx.token, flag: FLAGS.wildcard },
      targetOrigin: '*',
    });
  }

  if (data.op === 'partner' && origin.includes('harbor-link')) {
    flags.push(FLAGS.includes);
  }

  if (data.op === 'embed' && origin.startsWith(ctx.selfOrigin) && origin !== ctx.selfOrigin) {
    flags.push(FLAGS.prefix);
  }

  if (data.op === 'boot' && (!origin || origin === 'null')) {
    flags.push(FLAGS.nullOrigin);
  }

  if (data.op === 'region' && /harbor-link\.lab$/.test(origin)) {
    flags.push(FLAGS.suffix);
  }

  if (data.op === 'cfg') {
    const cfg = {};
    try {
      const src = data.json ? JSON.parse(String(data.json)) : data.config || {};
      unsafeDeepMerge(cfg, src);
    } catch {
      /* ignore */
    }
    if (cfg.admin === true || ({}.admin === true)) flags.push(FLAGS.proto);
    cleanupPollution();
  }

  if (data.op === 'go' && data.url) {
    if (ctx.navigate) ctx.navigate(String(data.url));
    if (/pm-open-url|evil-nav/i.test(String(data.url))) flags.push(FLAGS.nav);
  }

  if (data.op === 'session' && data.flag === FLAGS.wildcard && data.token) {
    flags.push(FLAGS.wildcard);
  }

  return { flags: unique(flags), replies };
}

function handleSecure(ev, ctx) {
  const allowed = new Set([ctx.selfOrigin]);
  if (!allowed.has(String(ev.origin || ''))) {
    return { flags: [], replies: [], blocked: 'Block-Unpinned-PostMessage-Origin' };
  }
  if (typeof ev.data === 'string') {
    return { flags: [], replies: [], blocked: 'Block-String-Json-Message' };
  }
  const data = ev.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { flags: [], replies: [], blocked: 'Block-Invalid-Message-Shape' };
  }
  if (Object.prototype.hasOwnProperty.call(data, '__proto__') || data.op === 'cfg') {
    return { flags: [], replies: [], blocked: 'Block-PostMessage-Prototype-Merge' };
  }
  const allow = new Set(['hello', 'ping']);
  if (!allow.has(data.op)) {
    return { flags: [], replies: [], blocked: 'Block-Dangerous-PostMessage-Op' };
  }
  if (data.op === 'hello') {
    return {
      flags: [],
      replies: [{ data: { op: 'ack' }, targetOrigin: ctx.selfOrigin }],
    };
  }
  return { flags: [], replies: [] };
}

function trophy(flags) {
  const need = [
    FLAGS.noOrigin,
    FLAGS.wildcard,
    FLAGS.includes,
    FLAGS.prefix,
    FLAGS.nullOrigin,
    FLAGS.suffix,
    FLAGS.proto,
    FLAGS.nav,
  ];
  if (need.every((f) => flags.includes(f))) return unique(flags.concat(FLAGS.complete));
  return unique(flags);
}

const STAGES = [
  {
    key: 'noOrigin',
    title: '1 · No origin check',
    origin: 'http://127.0.0.1:3899',
    data: { op: 'banner', html: '<b>from attacker</b>' },
    flag: FLAGS.noOrigin,
    rule: 'Block-Unpinned-PostMessage-Origin',
  },
  {
    key: 'wildcard',
    title: '2 · Wildcard targetOrigin',
    origin: 'http://127.0.0.1:3899',
    data: { op: 'hello' },
    flag: FLAGS.wildcard,
    rule: 'Block-Wildcard-Target-Origin',
    viaReply: true,
  },
  {
    key: 'includes',
    title: '3 · origin.includes',
    origin: 'http://evil-harbor-link.lab',
    data: { op: 'partner', id: 'acme' },
    flag: FLAGS.includes,
    rule: 'Block-Weak-Origin-Includes',
  },
  {
    key: 'prefix',
    title: '4 · origin.startsWith',
    origin: 'http://127.0.0.1:3800.attacker.lab',
    data: { op: 'embed', slot: 1 },
    flag: FLAGS.prefix,
    rule: 'Block-Weak-Origin-Prefix',
  },
  {
    key: 'nullOrigin',
    title: '5 · Origin null',
    origin: 'null',
    data: { op: 'boot' },
    flag: FLAGS.nullOrigin,
    rule: 'Block-Null-Origin-Message',
  },
  {
    key: 'suffix',
    title: '6 · /harbor-link\\.lab$/ ',
    origin: 'http://not-harbor-link.lab',
    data: { op: 'region', dc: 'ewr' },
    flag: FLAGS.suffix,
    rule: 'Block-Weak-Origin-Suffix',
  },
  {
    key: 'proto',
    title: '7 · JSON proto merge',
    origin: 'http://127.0.0.1:3899',
    data: { op: 'cfg', json: '{"__proto__":{"admin":true}}' },
    flag: FLAGS.proto,
    rule: 'Block-PostMessage-Prototype-Merge',
  },
  {
    key: 'nav',
    title: '8 · Unchecked op=go',
    origin: 'http://127.0.0.1:3899',
    data: { op: 'go', url: 'https://evil-nav.lab/pm-open-url' },
    flag: FLAGS.nav,
    rule: 'Block-Dangerous-PostMessage-Op',
  },
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    FLAGS,
    STAGES,
    handleVulnerable,
    handleSecure,
    trophy,
    cleanupPollution,
  };
}
