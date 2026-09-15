# OAuth Misconfiguration Laboratory (HarborNotes + HarborSocial)

Educational lab based on
[PayloadsAllTheThings — OAuth Misconfiguration](https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/)
(including
[authorization-code rule violation](https://swisskyrepo.github.io/PayloadsAllTheThings/OAuth%20Misconfiguration/#authorization-code-rule-violation))
and the five PortSwigger OAuth labs listed there.

HarborNotes is an OAuth **client**. HarborSocial is a broken **authorization server**. Together they implement implicit-flow email swap, CSRF profile linking, unrestricted `redirect_uri`, prefix-traversal token leaks, an open redirect, and reusable authorization codes.

## What happens when it works

1. **Implicit email swap** — JS posts `{ token, email }` to `/authenticate`. The token is only checked for existence. Change `email` to `carlos@harbor.notes` → `FLAG{oauth-implicit-email-swap}`.
2. **Forced linking** — `/oauth-linking` has no `state`. Attach `attacker.social` to admin, then sign in with the attacker profile → `FLAG{oauth-forced-link}`.
3. **`redirect_uri` hijack** — HarborSocial accepts any absolute redirect. Admin’s authorization code lands on the workbench `/steal`, then `/oauth-callback?code=` logs you in as admin → `FLAG{oauth-redirect-uri-hijack}`.
4. **Proxy page** — `redirect_uri` is a prefix match, so `/oauth-callback/../post/comment/comment-form` is accepted. That page `postMessage`s `window.location.href` to `*`. The fragment token calls HarborSocial `/oauth/me` → `FLAG{oauth-proxy-page-token}`.
5. **Open redirect** — same traversal to `/post/next?path=http://127.0.0.1:4099/steal-hash`. The browser keeps the fragment; `/oauth/me` again → `FLAG{oauth-open-redirect-token}`.
6. **Code reuse** — `POST /oauth/token` with the same `code` twice (RFC 6749 MUST deny the second use) → `FLAG{oauth-code-reuse}`.

`:9080` binds implicit email to `/oauth/me`, requires `state` on linking, drops `../` and absolute `/post/next` targets, rejects codes issued for a foreign `redirect_uri`, and treats codes as single-use.

## Architecture

```
Student
   │
   ├─:4000──► HarborNotes (OAuth client)
   ├─:4098──► HarborSocial (authorization server)
   ├─:4099──► Workbench / steal sink
   ├─:9080──► waf-proxy (HostNotes only)
   ├─:4586──► LocalStack Community (WAF 501)
   └─:4587──► waf-classic sidecar
```

| Service | Port | Role |
|---------|------|------|
| HarborNotes | 4000 | Vulnerable client |
| HarborSocial | 4098 | Vulnerable IdP |
| Workbench | 4099 | Stage runner + steal log |
| WAF VIP | 9080 | Implicit bind + CSRF + traversal + reuse |
| LocalStack | 4586 | Community |
| WAF Classic API | 4587 | `waf-regional` CRUD |

Ports sit above DNS rebinding (`3900` / `8980`).

## Accounts

| Site | User | Password |
|------|------|----------|
| HarborNotes | `alice` | `letmein` |
| HarborNotes | `admin` | `harboradmin` |
| HarborSocial | `alice.social` | `letmein` |
| HarborSocial | `admin.social` | `harboradmin` |
| HarborSocial | `attacker.social` | `evil` |

Carlos has no password on HarborNotes; implicit email swap is the intended path.

## Quick start

```bash
cd oauth-lab
bash scripts/run-local.sh
```

Open http://127.0.0.1:4099 and run the six stages. The same implicit swap through http://127.0.0.1:9080 should 403.

```bash
node exploit/oauth-attacks.js
node exploit/run-tests.js --port 4000 --expect vulnerable
node exploit/run-tests.js --port 9080 --expect blocked
```

## Defenses (`:9080`)

1. Call HarborSocial `/oauth/me` and reject `/authenticate` when `email` ≠ token subject.
2. Require `state=` on `/oauth-linking`.
3. Drop `../` and absolute `/post/next?path=`.
4. Compare the code’s issued `redirect_uri` to the registered callback.
5. Refuse a code the WAF has already seen.

Real IdPs should also exact-match `redirect_uri`, use authorization code + PKCE (not implicit), bind `state` to the session, and revoke tokens if a code is replayed.
