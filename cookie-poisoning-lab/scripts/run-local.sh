#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4575"
export AWS_PAGER=""

mkdir -p /tmp/cookie-poisoning-lab
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

stop_pid /tmp/cookie-poisoning-lab/webapp.pid
stop_pid /tmp/cookie-poisoning-lab/waf-proxy.pid
stop_pid /tmp/cookie-poisoning-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4575"
PORT=4575 node "$ROOT/waf/classic-api/server.js" >/tmp/cookie-poisoning-lab/waf-api.log 2>&1 &
echo $! >/tmp/cookie-poisoning-lab/waf-api.pid

echo "==> Starting HarborCart on :3400"
(cd "$ROOT/app" && PORT=3400 node server.js >/tmp/cookie-poisoning-lab/webapp.log 2>&1) &
echo $! >/tmp/cookie-poisoning-lab/webapp.pid

echo "==> Starting WAF proxy on :8480"
(cd "$ROOT/app/waf-proxy" && PORT=8480 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3400 node server.js >/tmp/cookie-poisoning-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/cookie-poisoning-lab/waf-proxy.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3400/health >/dev/null && curl -sf http://127.0.0.1:8480/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "Vulnerable app:  http://localhost:3400"
echo "WAF gate:        http://localhost:8480"
echo "WAF Classic API: http://localhost:4575"
echo "Workbench:       http://localhost:3400/workbench"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
