# HTTP Request Smuggling Lab (Node.js + AWS WAF + LocalStack)

Educational lab that demonstrates **CL.TE HTTP request smuggling** against a vulnerable Node.js reverse proxy, then blocks the same payloads with **AWS WAFv2-style rules** running in **LocalStack** (and enforced live on port `8180`).

## Architecture

```
Attacker
   │
   ├─:3100──► frontend (CL preference) ──► backend (TE preference)
   │              vulnerable desync              /admin secret
   │
   └─:8180──► waf-proxy (enforce rules) ──► frontend ──► backend
                    ▲
   LocalStack:4567──┘  WebACL "Request-Smuggling-Protection"
```

| Service | Host port | Role |
|---------|-----------|------|
| `frontend` | 3100 | Vulnerable proxy — trusts `Content-Length` when both CL and TE are present |
| `backend` | (internal) | Origin — prefers `Transfer-Encoding: chunked` |
| `waf-proxy` | 8180 | Enforces the same rules as the LocalStack WebACL |
| `localstack` | 4567 | AWS WAFv2 API (create/list WebACL) |

> Ports `3100` / `8180` / `4567` avoid clashing with the XSS-CSRF lab (`3000` / `4566`).

## Quick start

```bash
cd request-smuggling-lab
docker compose up --build -d
```

Wait for LocalStack to become ready, then create the WebACL (if init did not already run it):

```bash
# Inside LocalStack container
docker compose exec localstack bash /etc/localstack/init/ready.d/01-setup-waf.sh

# Or from the host (needs AWS CLI)
AWS_ENDPOINT_URL=http://localhost:4567 bash waf/setup-waf.sh
```

Open:

- Vulnerable app: http://localhost:3100
- WAF gate: http://localhost:8180
- LocalStack: http://localhost:4567

## Exploit (CL.TE)

The frontend reads **5** body bytes (`0\r\n\r\n`) because of `Content-Length`. The remaining bytes are treated as a **second request** and forwarded to `/admin`.

```bash
# Windows / cross-platform
node exploit/clte-smuggle.js 3100

# Through WAF — should return 403
node exploit/clte-smuggle.js 8180
```

Or with bash:

```bash
bash exploit/clte-smuggle.sh
bash exploit/test-waf-block.sh
bash exploit/te-obfuscation.sh
```

Successful smuggle response contains:

```text
FLAG{request-smuggling-success}
```

## WAF rules (LocalStack)

| Rule | What it blocks |
|------|----------------|
| `Block-CL-TE-Smuggling` | Both `Content-Length` and `Transfer-Encoding: chunked` |
| `Block-TE-Obfuscation` | `chunked,identity`, `xchunked`, whitespace tricks, etc. |
| `Block-Malformed-Content-Length` | `,` or spaces inside `Content-Length` |

These mirror common custom AWS WAF controls used alongside `AWSManagedRulesCommonRuleSet` on ALB/CloudFront.

Verify the ACL:

```bash
aws --endpoint-url=http://localhost:4567 --region us-east-1 \
  wafv2 list-web-acls --scope REGIONAL
```

## Why this is vulnerable

1. Client sends **both** `Content-Length` and `Transfer-Encoding: chunked`.
2. Frontend uses **CL** → stops reading after N bytes.
3. Leftover bytes stay on the connection and are parsed as another HTTP request.
4. That hidden request hits `/admin` without going through normal app controls.

In production, AWS WAF (and HTTP normalizers on ALB/CloudFront) reject ambiguous CL+TE requests before they reach your app.

## Lab notes

- For demos/YouTube: show exploit on `:3100`, then the same payload blocked on `:8180`, then `list-web-acls` on LocalStack.
- LocalStack stores the WebACL; **inline blocking** in this lab is done by `waf-proxy` (LocalStack does not front your HTTP port).
- On real AWS: associate the WebACL with an Application Load Balancer or CloudFront distribution.

## Tear down

```bash
docker compose down -v
```
