# Man-in-the-Middle (MitM) — session cookie capture

Educational lab: the attacker sits **between the victim and Clearwire Bank**, reads `Set-Cookie` / `Cookie`, and replays the session. That is the public-Wi-Fi / captive-portal case described alongside cookie attacks (F5, Invicti): intercept the channel, steal the session cookie, hijack the account.

The bank speaks **plain HTTP**. `sid` is not `Secure` and not `HttpOnly`.

## What happens when it works

1. Victim “joins airport Wi-Fi” and opens the hotspot URL (`:3580`) thinking it is the bank.
2. They sign in (`alice` / `letmein`).
3. The MitM copies `Set-Cookie: sid=…`, strips `Secure`/`HttpOnly` if present, and injects a banner into HTML.
4. The attacker replays `sid` against the real origin (`:3500`) and gets the dashboard — **no password**.
5. Optional: the MitM rewrites `amount=` on `POST /transfer`.

Flags:

- `FLAG{mitm-response-inject}` — injected into HTML the victim receives
- `FLAG{mitm-session-hijack}` — dashboard via stolen `sid`
- `FLAG{mitm-transfer-tamper}` — amount raised to `9999.00` in transit

## Architecture

```
Victim browser
   │
   ├─:3500──► Clearwire Bank (HTTP, sid not Secure/HttpOnly)
   │
   ├─:3580──► MitM hotspot (capture cookies, inject, tamper) ──► :3500
   │            /_mitm/  attacker console
   │
   ├─:8580──► waf-proxy (HSTS + sid HMAC wrap + block Via: Clearwire-MitM)
   │
   ├─:4576──► LocalStack Community (WAF 501)
   └─:4577──► waf-classic sidecar
```

| Service | Port | Role |
|---------|------|------|
| Bank | 3500 | Vulnerable origin |
| MitM hotspot | 3580 | Attacker-in-the-middle |
| WAF VIP | 8580 | Intended TLS/HSTS front door |
| LocalStack | 4576 | Community |
| WAF Classic API | 4577 | WebACL CRUD |

## Quick start

```bash
cd mitm-lab
bash scripts/run-local.sh
```

Open:

- Victim (hotspot): http://localhost:3580
- Attacker console: http://localhost:3580/_mitm/
- Real bank (still vulnerable): http://localhost:3500
- WAF VIP: http://localhost:8580

## Exploit

```bash
node exploit/mitm-hijack.js
node exploit/mitm-hijack.js --waf
node exploit/run-tests.js --expect vulnerable
node exploit/run-tests.js --expect blocked
```

Browser:

1. Use the hotspot (`:3580`), sign in as alice.
2. Confirm the red intercept banner (`FLAG{mitm-response-inject}`).
3. Open `/_mitm/` — stolen `sid` is listed.
4. Click **Replay stolen sid** — dashboard + `FLAG{mitm-session-hijack}`.
5. Send a $25 transfer through the hotspot — it becomes $9999 (`FLAG{mitm-transfer-tamper}`).
6. Replay the same `sid` to `:8580` — **403** `Block-Cleartext-Session-Cookie`.

## WAF

| Rule | What it blocks |
|------|----------------|
| `Block-Ssl-Strip-Channel` | `Via: Clearwire-MitM` (stripped/hotspot channel) |
| `Block-Cleartext-Session-Cookie` | `sid` without F5-style `w1.` HMAC wrap |
| (response) | `Strict-Transport-Security`, `HttpOnly` on wrapped `sid` |

A normal login on `:8580` still works. The stolen cookie from the HTTP hotspot does not.

## Why this is vulnerable

1. HTTP has no confidentiality — every proxy sees headers.
2. Session cookies without `Secure`/`HttpOnly` are both network-visible and script-visible.
3. Session tokens *are* the login; capturing them is account takeover.
4. Fix: HTTPS + HSTS, `Secure; HttpOnly; SameSite`, bind sessions at a TLS VIP, never issue sessions on a channel you do not control. A WAF can wrap cookies and refuse known intercept headers.

## Tear down

```bash
bash scripts/stop-local.sh
# or
docker compose down -v
```
