/**
 * Client gadgets that trust named DOM properties.
 * These are the bugs — they never read document.cookie or eval user JS.
 */
/* eslint-disable no-undef */
function runClobberGadgets(win) {
  const flags = [];
  const w = win;
  const d = win.document;

  function asString(value) {
    try {
      return String(value);
    } catch {
      return '';
    }
  }

  // 1. Bare id → window.IS_PREMIUM is a truthy HTMLElement
  if (w.IS_PREMIUM) flags.push('FLAG{domclob-window-id}');

  // 2. <a id> toString is the href (HTMLAnchorElement)
  if (w.ASSET_HOST) {
    const host = asString(w.ASSET_HOST);
    if (/evil-cdn|clobber-cdn/i.test(host)) flags.push('FLAG{domclob-anchor-tostring}');
  }

  // 3. <form id=SESSION><input name=priv> → SESSION.priv.value
  // (name=role would lose to Element.role IDL and never clobber)
  try {
    const session = w.SESSION;
    const priv =
      session &&
      (session.priv || (session.elements && (session.elements.priv || session.elements.namedItem && session.elements.namedItem('priv'))));
    if (priv && priv.value === 'admin') {
      flags.push('FLAG{domclob-form-nest}');
    }
  } catch {
    /* ignore */
  }

  // 4. Duplicate id=API → HTMLCollection; named item endpoint is an <a>
  try {
    const api = w.API;
    let endpoint = '';
    if (api && api.endpoint) endpoint = asString(api.endpoint);
    else if (api && api.length && api[1]) endpoint = asString(api[1]);
    if (/evil-api|clobber-api/i.test(endpoint)) flags.push('FLAG{domclob-htmlcollection}');
  } catch {
    /* ignore */
  }

  // 5. <img name=getElementById> shadows document.getElementById in browsers.
  // jsdom may keep the function; a named element is still the smash payload.
  let smashed = false;
  try {
    const gebi = d.getElementById;
    smashed = typeof gebi !== 'function' || (gebi && gebi.nodeType === 1);
  } catch {
    smashed = true;
  }
  try {
    if (d.querySelector && d.querySelector('[name="getElementById"]')) smashed = true;
  } catch {
    /* ignore */
  }
  if (smashed && w.SITE_BANNER && /clobber-gebi/i.test(asString(w.SITE_BANNER))) {
    flags.push('FLAG{domclob-gebi-smash}');
  }

  // 6. form.action is a fully-qualified URL, not the raw attribute
  try {
    const form = (d.forms && (d.forms.checkout || d.forms['checkout'])) || w.checkout;
    if (form && form.action && /clobber-action/i.test(asString(form.action))) {
      flags.push('FLAG{domclob-form-action}');
    }
  } catch {
    /* ignore */
  }

  if (flags.length >= 6) flags.push('FLAG{domclob-complete}');
  return flags;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runClobberGadgets };
}
