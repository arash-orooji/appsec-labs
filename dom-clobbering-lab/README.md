# Very advanced DOM Clobbering (HarborNotes)

Educational lab: the sanitizer strips `<script>`, `on*` handlers, and `javascript:` URLs. It still allows `id`, `name`, `href`, and `action`. First-party JavaScript later reads those names as if they were config. That is **DOM clobbering**, not XSS — no attacker script runs.

Based on [PortSwigger: DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) and Gareth Heyes’ HTMLCollection / `form.action` gadgets.

## Stages

| # | Gadget | What JS trusts | Flag |
|---|--------|----------------|------|
| 1 | `<div id=IS_PREMIUM>` | `window.IS_PREMIUM` is truthy | `FLAG{domclob-window-id}` |
| 2 | `<a id=ASSET_HOST href=…>` | `String(ASSET_HOST)` is the href | `FLAG{domclob-anchor-tostring}` |
| 3 | `<form id=SESSION><input name=priv>` | `SESSION.priv.value` (not `role` — IDL) | `FLAG{domclob-form-nest}` |
| 4 | Two `<a id=API>` + `name=endpoint` | HTMLCollection `API.endpoint` | `FLAG{domclob-htmlcollection}` |
| 5 | `<img name=getElementById>` | `document.getElementById` is an element | `FLAG{domclob-gebi-smash}` |
| 6 | `<form name=checkout action=…>` | `form.action` is an absolute URL | `FLAG{domclob-form-action}` |
| ★ | all six | `/api/eval` | `FLAG{domclob-complete}` |

## Architecture

```
Attacker
   │
   ├─:3700──► HarborNotes (sanitize, then trust named properties)
   │
   ├─:8780──► waf-proxy (reject known clobber ids/names)
   │
   ├─:4580──► LocalStack Community (WAF 501)
   └─:4581──► waf-classic sidecar
```

| Service | Port | Role |
|---------|------|------|
| HarborNotes | 3700 | Vulnerable origin |
| WAF VIP | 8780 | Named-property gadget filter |
| LocalStack | 4580 | Community |
| WAF Classic API | 4581 | WebACL CRUD |

## Quick start

```bash
cd dom-clobbering-lab
bash scripts/run-local.sh
```

Open http://127.0.0.1:3700/workbench — use the preset buttons, then **Live preview**.

The same payloads on http://127.0.0.1:8780/workbench should **403**.

## Exploit

```bash
node exploit/clobber.js
node exploit/clobber.js --waf
node exploit/run-tests.js --expect vulnerable
node exploit/run-tests.js --expect blocked
```

## WAF

| Rule | What it blocks |
|------|----------------|
| `Block-Clobbered-Window-Id` | `id=IS_PREMIUM` |
| `Block-Anchor-ToString-Gadget` | `id=ASSET_HOST` |
| `Block-Nested-Form-Clobber` | `SESSION` + `name=priv` |
| `Block-HtmlCollection-Clobber` | `id=API` + `name=endpoint` |
| `Block-GetElementById-Smash` | `name=getElementById` |
| `Block-Form-Action-Clobber` | named `checkout` + `action=` |

A benign `<p>release notes</p>` still evaluates.

## Why this is vulnerable

1. HTML named elements become properties of `window` / `document` / `form`.
2. `HTMLAnchorElement.prototype.toString` returns the URL; `HTMLFormElement.action` is a reflected URL.
3. Two nodes with the same `id` become an `HTMLCollection` with named items.
4. `img`/`form`/`iframe`/`embed`/`object` `name`s are also document properties — including `getElementById`.
5. A sanitizer that only bans script is not a security policy for *how JS reads the DOM*.
6. Fix: do not read config from `window.*` populated by HTML; use JSON in a non-clobberable closure, `Map`, or `iframe` sandbox without `allow-same-origin`. A WAF can additionally reject known gadget `id`/`name`s.

## Tear down

```bash
bash scripts/stop-local.sh
# or
docker compose down -v
```
