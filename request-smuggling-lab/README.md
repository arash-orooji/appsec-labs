# HTTP Request Smuggling Lab (Node.js + AWS WAF Classic + LocalStack Community)

Educational lab that demonstrates **CL.TE HTTP request smuggling** against a vulnerable Node.js reverse proxy, then blocks the same payloads with **AWS WAF Classic** (`waf-regional`).

> **LocalStack Community and WAF:** Community does **not** support WAFv2. On LocalStack `3.5` Community, `waf-regional` / `waf` also return HTTP 501 (`not yet implemented or pro feature`). This lab keeps the Community container so you can see that 501, and ships a small **WAF Classic API** (`waf-classic` on `:4569`) that speaks `aws waf-regional` JSON 1.1. Live blocking is done by `waf-proxy` on `:8180`.

## Architecture

```
Attacker
   │
   ├─:3100──► frontend (CL preference) ──► backend (TE preference)
   │              vulnerable desync              /admin secret
   │
   ├─:8180──► waf-proxy (enforce Classic WAF rules) ──► frontend ──► backend
   │
   ├─:4567──► LocalStack Community (WAFv2 / waf-regional → 501 Pro-only)
   │
   └─:4569──► waf-classic sidecar (aws waf-regional WebACL CRUD)
```

| Service | Host port | Role |
|---------|-----------|------|
| `frontend` | 3100 | Vulnerable proxy — trusts `Content-Length` when both CL and TE are present |
| `backend` | (internal / 3001 locally) | Origin — prefers `Transfer-Encoding: chunked` |
| `waf-proxy` | 8180 | Enforces the same rules as the WAF Classic WebACL |
| `localstack` | 4567 | LocalStack Community — WAF APIs are Pro-only (501) |
| `waf-classic` | 4569 | AWS WAF Classic API (`waf-regional`) used by `setup-waf.sh` |

> Ports `3100` / `8180` / `4567` / `4569` avoid clashing with the XSS-CSRF lab (`3000` / `8080` / `4566` / `4568`).

## Quick start

```bash
cd request-smuggling-lab
docker compose up --build -d
AWS_ENDPOINT_URL=http://localhost:4569 bash waf/setup-waf.sh
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open:

- Vulnerable app: http://localhost:3100
- WAF gate: http://localhost:8180
- LocalStack Community: http://localhost:4567
- WAF Classic API: http://localhost:4569

Confirm Community rejects WAFv2:

```bash
aws --endpoint-url=http://localhost:4567 --region us-east-1 \
  wafv2 list-web-acls --scope REGIONAL
# InternalFailure: API for service 'wafv2' not yet implemented or pro feature
```

## Exploit (CL.TE)

The frontend reads **5** body bytes (`0\r\n\r\n`) because of `Content-Length`. The remaining bytes are treated as a **second request** and forwarded to `/admin`.

```bash
# Vulnerable path — should print FLAG{request-smuggling-success}
node exploit/clte-smuggle.js 3100

# Through WAF — should return 403 Block-CL-TE-Smuggling
node exploit/clte-smuggle.js 8180
```

Or:

```bash
bash exploit/clte-smuggle.sh
bash exploit/test-waf-block.sh
bash exploit/te-obfuscation.sh
node exploit/run-tests.js --port 3100 --expect smuggled
node exploit/run-tests.js --port 8180 --expect blocked
```

Successful smuggle response contains:

```text
FLAG{request-smuggling-success}
```

## WAF rules (AWS WAF Classic — Community-compatible)

| Rule | What it blocks |
|------|----------------|
| `Block-CL-TE-Smuggling` | Both `Content-Length` and `Transfer-Encoding` containing `chunked` |
| `Block-TE-Obfuscation` | `identity`, `chunked,`, `,chunked`, `xchunked` |
| `Block-Malformed-Content-Length` | `,` inside `Content-Length` |

These mirror common custom AWS WAF controls used alongside `AWSManagedRulesCommonRuleSet` on ALB/CloudFront.

Verify the ACL against the Classic sidecar (not LocalStack `:4567`):

```bash
aws --endpoint-url=http://localhost:4569 --region us-east-1 \
  waf-regional list-web-acls
```

## Why this is vulnerable

1. Client sends **both** `Content-Length` and `Transfer-Encoding: chunked`.
2. Frontend uses **CL** → stops reading after N bytes.
3. Leftover bytes stay on the connection and are parsed as another HTTP request.
4. That hidden request hits `/admin` without going through normal app controls.

In production, AWS WAF (and HTTP normalizers on ALB/CloudFront) reject ambiguous CL+TE requests before they reach your app.

## Lab notes

- For demos: show exploit on `:3100`, then the same payload blocked on `:8180`, then `list-web-acls` on the Classic API.
- LocalStack Community stores nothing for WAF (501). The sidecar stores the WebACL; **inline blocking** is done by `waf-proxy`.
- On real AWS: associate the WebACL with an Application Load Balancer or CloudFront distribution.
- Do **not** switch this lab to `aws wafv2` on Community — both `wafv2` and `waf-regional` are Pro-only there.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
