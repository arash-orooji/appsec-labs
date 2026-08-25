#!/usr/bin/env bash
# Run the XSS-CSRF lab without Docker: Node app + WAF proxy + moto WAF Classic API.
# Prefer `docker compose up` (LocalStack Community) when Docker is available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4568}"

mkdir -p /tmp/xss-csrf-lab
cd "$ROOT"

if [[ ! -d "$ROOT/app/node_modules" ]]; then
  (cd "$ROOT/app" && npm install --production)
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

stop_pid /tmp/xss-csrf-lab/webapp.pid
stop_pid /tmp/xss-csrf-lab/waf-proxy.pid
stop_pid /tmp/xss-csrf-lab/attacker.pid
stop_pid /tmp/xss-csrf-lab/waf-api.pid

echo "==> Starting WAF Classic API emulator on :4568"
node "$ROOT/waf/classic-api/server.js" >/tmp/xss-csrf-lab/waf-api.log 2>&1 &
echo $! >/tmp/xss-csrf-lab/waf-api.pid

echo "==> Starting vulnerable app on :3000"
(cd "$ROOT/app" && PORT=3000 node server.js >/tmp/xss-csrf-lab/webapp.log 2>&1) &
echo $! >/tmp/xss-csrf-lab/webapp.pid

echo "==> Starting WAF proxy on :8080"
(cd "$ROOT/app/waf-proxy" && PORT=8080 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3000 node server.js >/tmp/xss-csrf-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/xss-csrf-lab/waf-proxy.pid

echo "==> Starting CSRF attacker origin on :9999"
python3 -m http.server 9999 --directory "$ROOT/exploit" >/tmp/xss-csrf-lab/attacker.log 2>&1 &
echo $! >/tmp/xss-csrf-lab/attacker.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3000/ >/dev/null && curl -sf http://127.0.0.1:8080/ >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "Vulnerable app:  http://localhost:3000"
echo "WAF gate:        http://localhost:8080"
echo "Attacker origin: http://localhost:9999/csrf-attack-vulnerable.html"
echo "WAF Classic API: http://localhost:4568  (waf-regional sidecar)"
echo ""
echo "PIDs in /tmp/xss-csrf-lab/*.pid  — stop with: bash $ROOT/scripts/stop-local.sh"
