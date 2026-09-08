#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4571}"
export AWS_PAGER=""

mkdir -p /tmp/cookie-bomb-lab
cd "$ROOT"

if [[ ! -d "$ROOT/app/node_modules" ]]; then
  (cd "$ROOT/app" && npm install --omit=dev)
fi

stop_pid() {
  local pidfile="$1"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile" || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

stop_pid /tmp/cookie-bomb-lab/webapp.pid
stop_pid /tmp/cookie-bomb-lab/waf-proxy.pid
stop_pid /tmp/cookie-bomb-lab/attacker.pid
stop_pid /tmp/cookie-bomb-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4571"
PORT=4571 node "$ROOT/waf/classic-api/server.js" >/tmp/cookie-bomb-lab/waf-api.log 2>&1 &
echo $! >/tmp/cookie-bomb-lab/waf-api.pid

echo "==> Starting ShopHome on :3200 (8KiB header cap)"
(cd "$ROOT/app" && PORT=3200 HEADER_LIMIT=8192 node --max-http-header-size=8192 server.js >/tmp/cookie-bomb-lab/webapp.log 2>&1) &
echo $! >/tmp/cookie-bomb-lab/webapp.pid

echo "==> Starting WAF proxy on :8280"
(cd "$ROOT/app/waf-proxy" && PORT=8280 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3200 node server.js >/tmp/cookie-bomb-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/cookie-bomb-lab/waf-proxy.pid

echo "==> Starting attacker origin on :9299"
python3 -m http.server 9299 --directory "$ROOT/exploit" >/tmp/cookie-bomb-lab/attacker.log 2>&1 &
echo $! >/tmp/cookie-bomb-lab/attacker.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3200/health >/dev/null && curl -sf http://127.0.0.1:8280/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "Vulnerable app:  http://localhost:3200"
echo "WAF gate:        http://localhost:8280"
echo "Malicious link:  http://localhost:9299/cookie-bomb.html"
echo "WAF Classic API: http://localhost:4571"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
