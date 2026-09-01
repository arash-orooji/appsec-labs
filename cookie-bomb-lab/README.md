# The Cookie Bomb Effect (Node.js + AWS WAF Classic + LocalStack Community)

Educational lab: a shop stores **unbounded tracking query parameters as cookies**. A malicious link plants several large `utm_*` cookies. After that, the victim’s `Cookie` header exceeds the HTTP header limit and **every later request fails** (`400 Bad Request`, `431 Request Header Fields Too Large`, or `414 URI Too Large`) until they clear cookies.

## What happens when it works

1. Victim clicks the malicious link.
2. Tracking parameter(s) are stored as cookies (`utm_source`, `utm_campaign`, …).
3. Cookies exceed the header size limit (this lab uses an **8KiB** cap, like many reverse proxies).
4. All further requests fail with `400` / `431` / `414`.
5. The victim cannot use the app until they clear cookies (`/clear`, or the browser cookie UI).

## Architecture

```
Attacker
   │
   ├─:3200──► ShopHome (stores utm_* in cookies, no size limit)
   │
   ├─:8280──► waf-proxy (oversized query / Cookie header) ──► ShopHome
   │
   ├─:4570──► LocalStack Community (WAF APIs → 501 Pro-only)
   │
   ├─:4571──► waf-classic sidecar (aws waf-regional WebACL CRUD)
   │
   └─:9299──► malicious “coupon” page (tracking pixels)
```

| Service | Host port | Role |
|---------|-----------|------|
| `webapp` | 3200 | Vulnerable shop — tracking query params become cookies |
| `waf-proxy` | 8280 | Enforces WAF Classic size rules |
| `attacker` | 9299 | Foreign origin that plants cookies via image pixels |
| `localstack` | 4570 | LocalStack Community (WAF is Pro-only) |
| `waf-classic` | 4571 | `waf-regional` API used by `setup-waf.sh` |

Ports avoid the XSS-CSRF (`3000` / `8080` / `4566`) and request-smuggling (`3100` / `8180` / `4567`) labs.

## Quick start

```bash
cd cookie-bomb-lab
docker compose up --build -d
AWS_ENDPOINT_URL=http://localhost:4571 bash waf/setup-waf.sh
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open:

- Shop: http://localhost:3200
- WAF gate: http://localhost:8280
- Malicious link: http://localhost:9299/cookie-bomb.html
- Same attack through WAF: http://localhost:9299/cookie-bomb-waf.html

## Exploit

```bash
# Plant 4 × 2500-byte utm_* cookies, then GET / — expect lockout
node exploit/cookie-bomb.js 3200

# Through WAF — planting request should be 403
node exploit/cookie-bomb.js 8280

node exploit/run-tests.js --port 3200 --expect vulnerable
node exploit/run-tests.js --port 8280 --expect blocked
```

The attacker page loads hidden pixels:

```text
http://localhost:3200/?utm_source=AAA…   (2500 bytes)
http://localhost:3200/?utm_medium=AAA…
http://localhost:3200/?utm_campaign=AAA…
http://localhost:3200/?utm_content=AAA…
```

then redirects to `/shop`. The combined `Cookie` header is larger than 8KiB.

## WAF rules (Classic, Community-compatible)

| Rule | What it blocks |
|------|----------------|
| `Block-Oversized-Query` | Query string ≥ 1024 bytes (stops planting) |
| `Block-Oversized-Cookie` | `Cookie` header ≥ 4096 bytes |

```bash
aws --endpoint-url=http://localhost:4571 --region us-east-1 \
  waf-regional list-web-acls
```

A normal campaign (`/?utm_source=newsletter`) still passes.

## Why this is vulnerable

1. Analytics/campaign code copies query parameters into cookies with no length check.
2. The attacker controls those parameters via a link the victim clicks.
3. Browsers send **all** matching cookies on later requests to that host.
4. Proxies and HTTP parsers reject oversize headers — a per-victim denial of service.

Application fix: cap cookie values (e.g. 64–200 bytes), allow-list parameter names, and refuse to persist raw query strings. WAF size limits stop the oversized plant before `Set-Cookie`.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
