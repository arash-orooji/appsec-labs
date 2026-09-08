# Session Puzzling — Bypass Two-Factor Authentication

Educational lab based on
[Using Session Puzzling to Bypass Two-Factor Authentication](https://dzone.com/articles/using-session-puzzling-to-bypass-two-factor-authen)
(DZone / Nikhil Mittal’s 2FA backup-code writeup).

VaultPay asks for a 2FA code after a correct password. While that prompt is showing, **settings and backup codes only check `session.confirmed`**, a flag set at password login. The dashboard checks `session.twoFactorComplete`. Same session, two meanings — session puzzling — so an attacker with the password can steal backup codes and finish 2FA without the SMS/TOTP.

## What happens when it works

1. Attacker submits username + password (`alice` / `letmein`).
2. Session state: password accepted, 2FA **not** done (`confirmed=true`, `twoFactorComplete=false`).
3. `GET /settings/backup-codes` (or `/api/backup-codes`) returns backup codes — it should have required completed 2FA.
4. Attacker posts a stolen backup code to `/2fa`.
5. Dashboard opens. Flag: `FLAG{session-puzzling-2fa-bypass}`.

## Architecture

```
Attacker
   │
   ├─:3300──► VaultPay (session.confirmed gates backup codes)
   │
   ├─:8380──► waf-proxy (blocks backup-code URIs while auth_step=pending_2fa)
   │
   ├─:4572──► LocalStack Community (WAF APIs → 501 Pro-only)
   │
   └─:4573──► waf-classic sidecar (aws waf-regional WebACL CRUD)
```

| Service | Host port | Role |
|---------|-----------|------|
| `webapp` | 3300 | Vulnerable VaultPay |
| `waf-proxy` | 8380 | Enforces WAF Classic byte-match rules |
| `localstack` | 4572 | LocalStack Community (WAF is Pro-only) |
| `waf-classic` | 4573 | `waf-regional` API used by `setup-waf.sh` |

Ports avoid the XSS-CSRF (`3000` / `8080`), request-smuggling (`3100` / `8180`), and cookie-bomb (`3200` / `8280`) labs.

## Quick start

```bash
cd session-puzzling-lab
docker compose up --build -d
AWS_ENDPOINT_URL=http://localhost:4573 bash waf/setup-waf.sh
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open:

- App: http://localhost:3300
- WAF gate: http://localhost:8380
- Login: `alice` / `letmein`

## Exploit

```bash
# Password → steal backup codes → complete 2FA → FLAG
node exploit/bypass-2fa.js 3300

# Through WAF — backup-code request should be 403
node exploit/bypass-2fa.js 8380

node exploit/run-tests.js --port 3300 --expect vulnerable
node exploit/run-tests.js --port 8380 --expect blocked
```

Browser path on `:3300`:

1. Sign in as `alice` / `letmein`.
2. Stay on the 2FA page (do **not** enter the SMS code).
3. Open **Settings → View backup codes** (or `/settings/backup-codes`).
4. Copy a code, choose **Lost your phone? Use a backup code**, submit it.
5. Dashboard shows `FLAG{session-puzzling-2fa-bypass}`.

The same clicks through `:8380` should 403 on the backup-codes page.

## WAF rules (Classic, Community-compatible)

| Rule | What it blocks |
|------|----------------|
| `Block-Backup-Codes-Pending-2FA` | URI contains `backup-codes` **and** Cookie contains `pending_2fa` |
| `Block-GetBackupCodes-Pending-2FA` | URI contains `GetBackupCodes` **and** Cookie contains `pending_2fa` |

Login, the 2FA form, and a completed session (`auth_step=complete`) still pass. A normal SMS 2FA login is allowed.

```bash
aws --endpoint-url=http://localhost:4573 --region us-east-1 \
  waf-regional list-web-acls
```

## Why this is vulnerable

1. Session variables are global to the session, not to one page.
2. `confirmed` is set when the password is accepted — a different fact than “2FA finished”.
3. Settings endpoints reuse that flag instead of `twoFactorComplete`.
4. Backup codes are equivalent to the second factor, so leaking them in the half-logged-in state **is** a 2FA bypass.

Application fix: gate every privileged route on a single “fully authenticated” flag (password **and** 2FA). Do not expose backup codes, recovery email, or session settings until `twoFactorComplete` is true. Use distinct session key names per concern.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
