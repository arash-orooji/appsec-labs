#!/usr/bin/env bash
# Run the request-smuggling lab without Docker: Node frontend/backend + WAF proxy + Classic API.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4569}"
export AWS_PAGER=""

mkdir -p /tmp/request-smuggling-lab

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

stop_pid /tmp/request-smuggling-lab/backend.pid
stop_pid /tmp/request-smuggling-lab/frontend.pid
stop_pid /tmp/request-smuggling-lab/waf-proxy.pid
stop_pid /tmp/request-smuggling-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4569"
PORT=4569 node "$ROOT/waf/classic-api/server.js" >/tmp/request-smuggling-lab/waf-api.log 2>&1 &
echo $! >/tmp/request-smuggling-lab/waf-api.pid

echo "==> Starting backend on :3001"
(cd "$ROOT/app/backend" && PORT=3001 ADMIN_SECRET='FLAG{request-smuggling-success}' node server.js >/tmp/request-smuggling-lab/backend.log 2>&1) &
echo $! >/tmp/request-smuggling-lab/backend.pid

echo "==> Starting vulnerable frontend on :3100"
(cd "$ROOT/app/frontend" && PORT=3100 BACKEND_HOST=127.0.0.1 BACKEND_PORT=3001 node server.js >/tmp/request-smuggling-lab/frontend.log 2>&1) &
echo $! >/tmp/request-smuggling-lab/frontend.pid

echo "==> Starting WAF proxy on :8180"
(cd "$ROOT/app/waf-proxy" && PORT=8180 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3100 node server.js >/tmp/request-smuggling-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/request-smuggling-lab/waf-proxy.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3100/health >/dev/null && curl -sf http://127.0.0.1:8180/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "Vulnerable proxy: http://localhost:3100"
echo "WAF gate:         http://localhost:8180"
echo "WAF Classic API:  http://localhost:4569  (waf-regional sidecar)"
echo "LocalStack:       http://localhost:4567  (Community — WAF APIs 501)"
echo ""
echo "PIDs in /tmp/request-smuggling-lab/*.pid — stop with: bash $ROOT/scripts/stop-local.sh"
