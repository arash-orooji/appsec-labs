# XSS & CSRF Lab (Node.js + AWS WAF Classic + LocalStack Community)

Educational lab that demonstrates **reflected XSS** and **CSRF** against a vulnerable Node.js app, then blocks the same payloads with **AWS WAF Classic** (`waf-regional`).

> **LocalStack Community and WAF:** Community does **not** support WAFv2. On LocalStack `3.5` Community, `waf-regional` / `waf` also return HTTP 501 (`not yet implemented or pro feature`). This lab keeps the Community container so you can see that 501, and ships a small **WAF Classic API** (`waf-classic` on `:4568`) that speaks `aws waf-regional` JSON 1.1. Live blocking is done by `waf-proxy` on `:8080`.

## Architecture

```
Attacker
   │
   ├─:3000──► webapp (reflected XSS + CSRF with no token)
   │
   ├─:8080──► waf-proxy (enforce Classic WAF rules) ──► webapp
   │
   ├─:4566──► LocalStack Community (WAFv2 / waf-regional → 501 Pro-only)
   │
   ├─:4568──► waf-classic sidecar (aws waf-regional WebACL CRUD)
   │              ▲
   │              └── setup-waf.sh creates WebACL "XSS-CSRF-Protection"
   │
   └─:9999──► attacker origin (auto-submit CSRF HTML)
```

| Service | Host port | Role |
|---------|-----------|------|
| `webapp` | 3000 | Vulnerable app — XSS reflected in `/search`, CSRF on `POST /update-email` |
| `waf-proxy` | 8080 | Enforces the same rules as the WAF Classic WebACL |
| `attacker` | 9999 | Foreign origin that hosts the CSRF form |
| `localstack` | 4566 | LocalStack Community — WAF APIs are Pro-only (501) |
| `waf-classic` | 4568 | AWS WAF Classic API (`waf-regional`) used by `setup-waf.sh` |

## Quick start

```bash
cd xss-csrf-lab
docker compose up --build -d
```

Wait for LocalStack to become ready, then create the WebACL (Community has no WAF APIs, so this talks to `:4568`):

```bash
AWS_ENDPOINT_URL=http://localhost:4568 bash waf/setup-waf.sh
```

Confirm Community rejects WAFv2:

```bash
aws --endpoint-url=http://localhost:4566 --region us-east-1 \
  wafv2 list-web-acls --scope REGIONAL
# InternalFailure: API for service 'wafv2' not yet implemented or pro feature
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open:

- Vulnerable app: http://localhost:3000
- WAF gate: http://localhost:8080
- CSRF attacker page: http://localhost:9999/csrf-attack-vulnerable.html
- LocalStack Community: http://localhost:4566
- WAF Classic API: http://localhost:4568

## XSS payloads (reflected)

These URLs hit `/search` and are echoed **unsanitized**:

```text
http://localhost:3000/search?q=<script>alert(1)</script>
http://localhost:3000/search?q=<script>alert(document.cookie)</script>
http://localhost:3000/search?q=<img src=x onerror=alert(1)>
http://localhost:3000/search?q="><svg/onload=alert(1)>
```

```bash
bash exploit/test-xss.sh http://localhost:3000
# Through WAF — should return 403
bash exploit/test-xss.sh http://localhost:8080
```

Successful reflection contains the raw payload in `You searched for: …`.

## CSRF payload

The profile form posts to `/update-email` with **no CSRF token** and **no Origin/Referer check**. From a foreign origin:

```html
<html>
  <body>
    <form action="http://localhost:3000/update-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

Hosted at http://localhost:9999/csrf-attack-vulnerable.html (and the WAF variant at `csrf-attack-waf.html`).

```bash
bash exploit/test-csrf.sh http://localhost:3000
# Through WAF — should return 403
bash exploit/test-csrf.sh http://localhost:8080
```

Successful CSRF response contains:

```text
Email updated to: attacker@evil.com
```

## WAF rules (AWS WAF Classic — Community-compatible)

| Rule | What it blocks |
|------|----------------|
| `Block-XSS-Rule` | XSS match on query string, URI, and body (`XssMatchSet`) |
| `Block-CSRF-Rule` | `POST` + URI `/update-email` + **not** a same-origin `Origin` header |

Create / verify the ACL against the Classic sidecar (not LocalStack `:4566`):

```bash
aws --endpoint-url=http://localhost:4568 --region us-east-1 \
  waf-regional list-web-acls
```

Automated block checks (benign traffic must still pass):

```bash
node exploit/run-tests.js --target http://localhost:3000 --expect vulnerable
node exploit/run-tests.js --target http://localhost:8080 --expect blocked
bash exploit/test-waf-block.sh
```

## Why this is vulnerable

1. `/search` interpolates `req.query.q` into HTML with no encoding → reflected XSS.
2. `POST /update-email` changes email with no CSRF token, Origin, or Referer check.
3. Session cookie is not `HttpOnly`, so `alert(document.cookie)` can show it after XSS.

In production, AWS WAF Classic (or WAFv2 on real AWS / LocalStack Pro) inspects the same fields before the request reaches the app.

## Lab notes

- For demos: show exploit on `:3000`, then the same payload blocked on `:8080`, then `list-web-acls` on LocalStack.
- LocalStack stores the WebACL; **inline blocking** in this lab is done by `waf-proxy` (LocalStack does not front your HTTP port).
- On real AWS: associate the WebACL with an Application Load Balancer or CloudFront distribution.
- Do **not** switch this lab to `aws wafv2` on Community — both `wafv2` and `waf-regional` are Pro-only there. Use the `:4568` sidecar for Classic CRUD.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
