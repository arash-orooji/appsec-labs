# XSS & CSRF Lab (Node.js + AWS WAF Classic + LocalStack Community)

Educational lab that demonstrates **reflected XSS** and **CSRF** against a vulnerable Node.js app, then blocks the same payloads with **AWS WAF Classic** (`waf-regional`) on **LocalStack Community**.

> **Why Classic, not WAFv2?** LocalStack Community does **not** support WAFv2 (`aws wafv2 …` is Pro-only). This lab uses the WAF Classic APIs (`aws waf-regional`) that Community can host, and a local `waf-proxy` that enforces the same rules on HTTP traffic.

## Architecture

```
Attacker
   │
   ├─:3000──► webapp (reflected XSS + CSRF with no token)
   │
   ├─:8080──► waf-proxy (enforce Classic WAF rules) ──► webapp
   │              ▲
   │   LocalStack:4566──┘  WebACL "XSS-CSRF-Protection" (waf-regional)
   │
   └─:9999──► attacker origin (auto-submit CSRF HTML)
```

| Service | Host port | Role |
|---------|-----------|------|
| `webapp` | 3000 | Vulnerable app — XSS reflected in `/search`, CSRF on `POST /update-email` |
| `waf-proxy` | 8080 | Enforces the same rules as the LocalStack WAF Classic WebACL |
| `attacker` | 9999 | Foreign origin that hosts the CSRF form |
| `localstack` | 4566 | AWS WAF Classic API (`waf` / `waf-regional`) — **not** WAFv2 |

## Quick start

```bash
cd xss-csrf-lab
docker compose up --build -d
```

Wait for LocalStack to become ready, then create the WebACL if init did not already run it:

```bash
# Inside LocalStack container
docker compose exec localstack bash /etc/localstack/init/ready.d/01-setup-waf.sh

# Or from the host (needs AWS CLI)
AWS_ENDPOINT_URL=http://localhost:4566 bash waf/setup-waf.sh
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open:

- Vulnerable app: http://localhost:3000
- WAF gate: http://localhost:8080
- CSRF attacker page: http://localhost:9999/csrf-attack-vulnerable.html
- LocalStack: http://localhost:4566

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

## WAF rules (LocalStack Community — Classic API)

| Rule | What it blocks |
|------|----------------|
| `Block-XSS-Rule` | XSS match on query string, URI, and body (`XssMatchSet`) |
| `Block-CSRF-Rule` | `POST` + URI `/update-email` + **not** a same-origin `Origin` header |

Verify the ACL:

```bash
aws --endpoint-url=http://localhost:4566 --region us-east-1 \
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
- Do **not** switch this lab to `aws wafv2` unless you are on LocalStack Pro.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
