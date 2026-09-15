# Cross-Site WebSocket Hijacking (CSWSH)

Educational lab: Harbor Markets authenticates its trading sockets with the `sid` **cookie** and treats the HTTP Upgrade as if it were first-party. A page on another origin opens `new WebSocket(...)`, the browser attaches the cookie, and the attacker reads positions and places orders. That is CSRF against the handshake — not XSS, and not cookie theft via `document.cookie`.

## Stages

| # | Socket | Handshake flaw | Flag |
|---|--------|----------------|------|
| 1 | `/ws/desk` | No `Origin` check | `FLAG{cswsh-classic}` |
| 1b | `/ws/desk` + `{op:"positions"}` | Same socket, private book | `FLAG{cswsh-positions}` |
| 1c | `/ws/desk` + `{op:"order"}` | Forced sell | `FLAG{cswsh-forced-order}` |
| 2 | `/ws/quotes` | `Origin.includes('harbor')` | `FLAG{cswsh-origin-bypass}` |
| 3 | `/ws/iframe` | Allows `Origin: null` | `FLAG{cswsh-null-origin}` |

Stage 2 cannot be spoofed from a browser on `:3699` (Origin is not script-controlled). The CLI sends `Origin: http://evil-harbor.lab`.

## Architecture

```
Attacker browser (http://127.0.0.1:3699)
   │  new WebSocket('ws://127.0.0.1:3600/ws/desk')
   │  Cookie: sid=…   Origin: http://127.0.0.1:3699
   │
   ├─:3600──► Harbor Markets (cookie-auth WS, weak/missing Origin)
   │
   ├─:8680──► waf-proxy (exact Origin + wst ticket + HSTS)
   │
   ├─:4578──► LocalStack Community (WAF 501)
   └─:4579──► waf-classic sidecar
```

| Service | Port | Role |
|---------|------|------|
| Harbor Markets | 3600 | Vulnerable origin |
| Attacker pages | 3699 | Foreign origin |
| WAF VIP | 8680 | Intended front door |
| LocalStack | 4578 | Community |
| WAF Classic API | 4579 | WebACL CRUD |

Use **127.0.0.1** consistently. `localhost` and `127.0.0.1` are different cookie sites.

## Quick start

```bash
cd cswsh-lab
bash scripts/run-local.sh
```

Open:

- Desk: http://127.0.0.1:3600  (`alice` / `letmein`)
- Attacker: http://127.0.0.1:3699/hijack
- WAF VIP: http://127.0.0.1:8680

## Exploit

```bash
node exploit/cswsh-hijack.js
node exploit/cswsh-hijack.js --waf
node exploit/run-tests.js --expect vulnerable
node exploit/run-tests.js --expect blocked
```

Browser:

1. Sign in on `:3600`.
2. Open `:3699/hijack` and connect — tape shows the three desk flags.
3. Repeat the same URL against `:8680` — **403** `Block-Cross-Origin-Websocket`.
4. Sign in on `:8680` — the desk socket still works (VIP Origin + `wst.` ticket).

## WAF

| Rule | What it blocks |
|------|----------------|
| `Block-Cross-Origin-Websocket` | Upgrade `Origin` not the VIP |
| `Block-Null-Origin-Websocket` | `Origin: null` / missing |
| `Block-Weak-Origin-Bypass` | Lookalike `evil-harbor` Origin |
| `Block-Missing-Ws-Ticket` | No `wst.` protocol / cookie |
| `Block-Ws-Ticket-Mismatch` | Ticket not bound to wrapped `sid` |
| (response) | `Strict-Transport-Security`, `HttpOnly` + `SameSite=Strict` on `sid` |

## Why this is vulnerable

1. The WebSocket handshake is an HTTP request; cookies are sent automatically.
2. `Origin` is the anti-CSRF signal for that handshake — if you ignore it (or match with `includes`), any site can ride the session.
3. `Origin: null` (sandboxed iframe, some redirects) is not “first party”.
4. Fix: allowlist exact origins, bind a CSRF/ticket to the session (`Sec-WebSocket-Protocol` or a custom header the handshake can see), `SameSite=Strict` / `HttpOnly` cookies, and refuse `null`.

## Tear down

```bash
bash scripts/stop-local.sh
# or
docker compose down -v
```
