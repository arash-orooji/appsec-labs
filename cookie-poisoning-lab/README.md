# Advanced Cookie Poisoning (HarborCart + AWS WAF Classic)

Educational lab based on
[F5: What Is Cookie Poisoning?](https://www.f5.com/glossary/cookie-poisoning)
and
[Invicti: Cookie poisoning](https://www.invicti.com/learn/cookie-poisoning).

**Poisoning ≠ hijacking.** Hijacking *reads* a cookie (often a session ID). Poisoning *changes* cookie fields the application trusts — identity, role, price, encrypted blobs — before they are sent back to the server. HarborCart stores all of that in cookies the browser can edit.

## What happens when it works

1. The app issues unsigned / weakly protected cookies (`cart`, `identity`, `authz`, `vault`, `legacy`).
2. The attacker edits them (DevTools, crafted `Cookie:` header, or `/workbench`).
3. The next request is accepted as a cheaper cart, another user, or an admin.
4. Advanced stages forge integrity: HMAC that does not cover `role=`, AES-CBC with no MAC (IV bit-flip), MD5 prefix-MAC hash-length extension.
5. Through `:8480` the same edits are rejected (F5-style cookie HMAC wrap + Classic signatures).

## Stages

| # | Cookie | Flaw | Flag |
|---|--------|------|------|
| 1 | `cart` | Client-supplied `price=` | `FLAG{cookie-poison-cart-price}` |
| 2 | `identity` | Base64 JSON, no signature | `FLAG{cookie-poison-identity}` |
| 3 | `authz` | HMAC-SHA256 covers `user=` only | `FLAG{cookie-poison-hmac-gap}` |
| 4 | `vault` | AES-128-CBC, no MAC — flip `admin=0`→`1` via IV | `FLAG{cookie-poison-cbc-bitflip}` |
| 5 | `legacy` + `lsig` | `MD5(pepper \|\| data)` length extension | `FLAG{cookie-poison-hash-extend}` |
| ★ | all five at once | `/trophy` | `FLAG{cookie-poisoning-complete}` |

## Architecture

```
Attacker
   │
   ├─:3400──► HarborCart (trusts poisoned cookies)
   │
   ├─:8480──► waf-proxy (HMAC-wrap Set-Cookie, verify on the way in)
   │
   ├─:4574──► LocalStack Community (WAF APIs → 501 Pro-only)
   │
   └─:4575──► waf-classic sidecar (aws waf-regional WebACL CRUD)
```

| Service | Host port | Role |
|---------|-----------|------|
| `webapp` | 3400 | Vulnerable HarborCart |
| `waf-proxy` | 8480 | Cookie integrity + Classic byte matches |
| `localstack` | 4574 | Community LocalStack |
| `waf-classic` | 4575 | `waf-regional` API for `setup-waf.sh` |

Ports avoid XSS-CSRF (`3000`/`8080`), request-smuggling (`3100`/`8180`), cookie-bomb (`3200`/`8280`), and session-puzzling (`3300`/`8380`).

## Quick start

```bash
cd cookie-poisoning-lab
docker compose up --build -d
AWS_ENDPOINT_URL=http://localhost:4575 bash waf/setup-waf.sh
```

Without Docker:

```bash
bash scripts/run-local.sh
```

Open http://localhost:3400/workbench and run the five poisons. Same clicks on http://localhost:8480/workbench should 403.

## Exploit

```bash
node exploit/poison.js 3400
node exploit/poison.js 8480

node exploit/run-tests.js --port 3400 --expect vulnerable
node exploit/run-tests.js --port 8480 --expect blocked
```

CBC: plaintext `uid=101&admin=0` sits in the first block; XOR IV byte 14 with `0x01` turns `0` into `1`.

Hash-length extension: pepper is **8 bytes**. Forge `user=guest || MD5-glue || user=admin` and a matching MD5 continuation of `lsig`.

## WAF (Classic + integrity wrap)

F5’s defense is not “block `role=admin` forever” — it is **not trusting cookies the WAF did not mint**. The proxy HMAC-wraps `Set-Cookie` (`w1.<mac>.<value>`). A client-side edit is missing or breaks that MAC.

| Rule | What it blocks |
|------|----------------|
| `Block-Cookie-Integrity` | Protected cookie without a valid `w1.` wrap |
| `Block-Poisoned-Cart-Price` | Cookie contains `price=0` |
| `Block-Forged-Admin-Role` | Cookie contains `role=admin` |

Benign shopping with wrapped cookies still loads.

## Why this is vulnerable

1. Anything the browser stores can be rewritten (Invicti client-side poisoning).
2. Base64 / “encryption” without a MAC is reversible or bit-flippable.
3. An HMAC that omits a field is an unsigned field.
4. `H(secret || data)` with MD5/SHA-1 is length-extendable.
5. The fix is server-side prices and identity, plus HMAC/AEAD over **all** trusted fields (or do not put them in cookies). A WAF can additionally bind outbound cookies so tampering never reaches the app.

## Tear down

```bash
docker compose down -v
# or
bash scripts/stop-local.sh
```
