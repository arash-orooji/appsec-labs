# Advanced DNS Rebinding Laboratory (HarborHome)

Educational lab based on
[PayloadsAllTheThings — DNS Rebinding](https://swisskyrepo.github.io/PayloadsAllTheThings/DNS%20Rebinding/)
and the
[protection-bypasses](https://swisskyrepo.github.io/PayloadsAllTheThings/DNS%20Rebinding/#protection-bypasses)
section (NCC Group / Singularity notes: perimeter resolvers drop RFC1918 and often `127.0.0.0/8`, but not always `0.0.0.0` or CNAME).

HarborHome is a LAN router/IoT panel. It has **no CSRF token** and **no Host pin**. The browser same-origin policy is the only gate. DNS rebinding defeats that gate: the attacker name first points at the attacker, then at the device.

Chrome's stub resolver is not under this lab's control. The lab therefore ships **its own DNS** (UDP/TCP) plus a **same-origin flip gateway** so you can see both the packet-level answers and a real browser `fetch` after the name "flips."

## What happens when it works

1. Victim loads `http://classic.rebind.lab/` — first A is `203.0.113.50` (attacker page, TTL 1).
2. Attacker JS waits; TTL expires; the next lookup returns loopback / `0.0.0.0` / a CNAME.
3. `fetch('/api/wan-config')` is still same-origin. The browser sends `Host: classic.rebind.lab` to the device.
4. HarborHome trusts that Host and returns WAN credentials plus a stage flag.

Through `:8980` the same Host is rejected (VIP allowlist + Classic byte matches).

## Stages (PAT bypasses)

| # | Name | Second answer | Why it bypasses a typical filter | Flag |
|---|------|---------------|----------------------------------|------|
| 1 | `classic.rebind.lab` | A `127.0.0.1` | Baseline rebind. Dropped if the filter covers `127/8`. | `FLAG{dnsrebind-classic}` |
| 2 | `zero.rebind.lab` | A `0.0.0.0` | Many filters drop `127/8` but not the unspecified address. | `FLAG{dnsrebind-zero}` |
| 3 | `cname-int.rebind.lab` | CNAME `target.local` | Filtered response has **no private A**. The *internal* stub resolves `target.local`. | `FLAG{dnsrebind-cname-int}` |
| 4 | `cname-localhost.rebind.lab` | CNAME `localhost` | Same idea: CNAME to `localhost`. | `FLAG{dnsrebind-cname-localhost}` |
| ★ | all four | `/api/trophy` | | `FLAG{dnsrebind-complete}` |

## Architecture

```
Attacker / student
   │
   ├─:3900──► HarborHome (no Host pin; flags from Host)
   ├─:3998──► Flip gateway (first hits = attacker page; after /flip proxy to :3900)
   ├─:3999──► Workbench (/api/dns-lookup, /api/rebind-http)
   ├─:5354──► Lab DNS raw (TTL 0/1 A + CNAME)
   ├─:5355──► Perimeter filter (drop RFC1918 + 127/8; keep 0.0.0.0 + CNAME)
   ├─:5356──► Strict filter (also drop 0.0.0.0, CNAME localhost, CNAME *.local)
   ├─:8980──► waf-proxy (Host pin 127.0.0.1 / localhost)
   ├─:4584──► LocalStack Community (WAF APIs → 501 Pro-only)
   └─:4585──► waf-classic sidecar (aws waf-regional WebACL CRUD)
```

| Service | Host port | Role |
|---------|-----------|------|
| HarborHome | 3900 | Vulnerable IoT / router origin |
| Flip gateway | 3998 | Same-origin SOP demo |
| Workbench | 3999 | DNS + HTTP rebind console |
| DNS raw / perimeter / strict | 5354 / 5355 / 5356 | Lab resolvers |
| WAF VIP | 8980 | Host pin + Classic signatures |
| LocalStack | 4584 | Community |
| WAF Classic API | 4585 | `waf-regional` for `setup-waf.sh` |

Ports avoid earlier labs (XSS/CSRF `3000`, smuggling `3100`, cookie-bomb `3200`, session-puzzling `3300`, cookie-poisoning `3400`, MitM `3500`, CSWSH `3600`, DOM clobbering `3700`, postMessage `3800`).

## Quick start

```bash
cd dns-rebinding-lab
bash scripts/run-local.sh
```

Open:

- Workbench: http://127.0.0.1:3999 — four PAT stages, trophy, and **Replay through WAF VIP**
- Flip gateway: http://127.0.0.1:3998 — same-origin `fetch` after `POST /flip`
- HarborHome: http://127.0.0.1:3900
- WAF VIP: http://127.0.0.1:8980 — legitimate `Host` still works; rebind names 403

```bash
# optional packet view if dig is installed
dig @127.0.0.1 -p 5354 classic.rebind.lab +norecurse
dig @127.0.0.1 -p 5354 classic.rebind.lab +norecurse
dig @127.0.0.1 -p 5355 zero.rebind.lab
```

Docker:

```bash
docker compose up --build -d
AWS_ENDPOINT_URL=http://localhost:4585 bash waf/setup-waf.sh
```

## Exploit

```bash
node exploit/rebind.js
node exploit/rebind.js --port 8980

node exploit/run-tests.js --port 3900 --expect vulnerable
node exploit/run-tests.js --port 8980 --expect blocked
```

`--expect vulnerable`: raw 5354 flip, perimeter keeps `0.0.0.0` and both CNAMEs, workbench HTTP collects four flags, gateway `/flip` reads WAN config, trophy.

`--expect blocked`: WAF Host pin 403s every rebind name / `target.local` / `0.0.0.0`; legitimate `GET /` still 200; perimeter still drops `127.0.0.1`; strict 5356 drops the PAT bypasses.

## Defenses (what `:8980` does)

1. **Host allowlist** — only `127.0.0.1` and `localhost` (with the lab ports). Rebind names never reach HarborHome.
2. **Classic byte matches** — `Host` contains `rebind.lab`, `target.local`, or `0.0.0.0`.
3. **Strict DNS** (`:5356`) — drop `0.0.0.0` and CNAME-to-internal / CNAME-to-localhost, not only RFC1918.

Real products also: DNS pinning (Chrome), `dns-prefetch` / cache, blocking private IP navigation from public pages, and authenticating the IoT API so SOP is not the only control.

## Notes

- First lookup of each attacker name is always `203.0.113.50` (TEST-NET-3). `POST /api/dns-reset` on the workbench clears hit counters.
- CNAME follow uses the **raw** resolver to simulate the internal stub after the perimeter returned only a CNAME.
- Do not point a production resolver at this zone.
