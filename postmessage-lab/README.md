# Very complex postMessage lab (HarborLink)

Educational lab: HarborLink’s partner portal treats `window.postMessage` like a first-party API. The browser’s only sender identity is `event.origin`. If you skip it, use `includes` / `startsWith` / a suffix regex, allow `null`, send with `targetOrigin: '*'`, or deep-merge JSON, a foreign window drives your sinks.

## Stages

| # | Gadget | Forged `event.origin` | Flag |
|---|--------|----------------------|------|
| 1 | No origin check + HTML sink (`op=banner`) | `http://127.0.0.1:3899` | `FLAG{pm-no-origin}` |
| 2 | Reply / announce with `targetOrigin: '*'` | attacker receives session | `FLAG{pm-wildcard-send}` |
| 3 | `origin.includes('harbor-link')` | `http://evil-harbor-link.lab` | `FLAG{pm-origin-includes}` |
| 4 | `origin.startsWith(selfOrigin)` | `http://127.0.0.1:3800.attacker.lab` | `FLAG{pm-origin-prefix}` |
| 5 | `origin === 'null'` allowed | sandboxed iframe | `FLAG{pm-null-origin}` |
| 6 | `/harbor-link\.lab$/` | `http://not-harbor-link.lab` | `FLAG{pm-origin-suffix}` |
| 7 | `unsafeDeepMerge` + `{"__proto__":{"admin":true}}` | attacker | `FLAG{pm-proto}` |
| 8 | `op=go` → URL from the message | attacker | `FLAG{pm-open-url}` |
| ★ | all eight | `/api/dispatch-all` | `FLAG{pm-complete}` |

A browser cannot spoof `event.origin`. Stages 3, 4, and 6 are run through `/api/dispatch` (same handler the portal uses). Stages 1, 2, 5, 7, and 8 also run as real `postMessage` from `:3899`.

## Architecture

```
Attacker window (:3899)
   │  postMessage(...)
   │
   ├─:3800──► HarborLink portal (vulnerable listeners)
   │
   ├─:8880──► waf-proxy (rewrite listeners + block dispatch gadgets)
   │
   ├─:4582──► LocalStack Community
   └─:4583──► waf-classic sidecar
```

| Service | Port | Role |
|---------|------|------|
| HarborLink | 3800 | Vulnerable origin |
| Attacker | 3899 | Foreign origin |
| WAF VIP | 8880 | Exact origin + allowlisted ops |
| LocalStack | 4582 | Community |
| WAF Classic API | 4583 | WebACL CRUD |

## Quick start

```bash
cd postmessage-lab
bash scripts/run-local.sh
```

Open http://127.0.0.1:3800/workbench — per-stage buttons or **★ run all**. Same clicks on http://127.0.0.1:8880/workbench should **403**.

## Exploit

```bash
node exploit/postmessage.js
node exploit/postmessage.js --waf
node exploit/run-tests.js --expect vulnerable
node exploit/run-tests.js --expect blocked
```

## WAF

| Rule | What it blocks |
|------|----------------|
| `Block-Unpinned-PostMessage-Origin` | `op=banner` from any origin |
| `Block-Wildcard-Target-Origin` | `op=hello` session leak |
| `Block-Weak-Origin-Includes` | `evil-harbor-link` |
| `Block-Weak-Origin-Prefix` | `selfOrigin` + extra suffix |
| `Block-Null-Origin-Message` | `origin: null` |
| `Block-Weak-Origin-Suffix` | `/harbor-link.lab$/` lookalike |
| `Block-PostMessage-Prototype-Merge` | `__proto__` / `op=cfg` |
| `Block-Dangerous-PostMessage-Op` | `op=go` |
| (response) | `/listeners-vuln.js` rewritten to `handleSecure` |

A same-origin `{op:'ping'}` still returns 200.

## Why this is vulnerable

1. `postMessage` is cross-origin by design; cookies are not the check.
2. `event.origin` is exact. `includes`, `startsWith`, and suffix regexes are not.
3. `Origin: null` is a sandbox / `data:` document, not first-party.
4. `targetOrigin: '*'` gives the payload to every embedder.
5. JSON + recursive merge is prototype pollution.
6. Fix: exact allowlist, structured clone (not `JSON.parse` of strings), allowlisted `op`s, `targetOrigin` set to the concrete partner origin. A WAF can additionally refuse the known gadget shapes and swap in a pinned listener.

## Tear down

```bash
bash scripts/stop-local.sh
# or
docker compose down -v
```
