#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4581"
export AWS_PAGER=""

mkdir -p /tmp/dom-clobbering-lab
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

stop_pid /tmp/dom-clobbering-lab/webapp.pid
stop_pid /tmp/dom-clobbering-lab/waf-proxy.pid
stop_pid /tmp/dom-clobbering-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4581"
PORT=4581 node "$ROOT/waf/classic-api/server.js" >/tmp/dom-clobbering-lab/waf-api.log 2>&1 &
echo $! >/tmp/dom-clobbering-lab/waf-api.pid

echo "==> Starting HarborNotes on :3700"
(cd "$ROOT/app" && PORT=3700 node server.js >/tmp/dom-clobbering-lab/webapp.log 2>&1) &
echo $! >/tmp/dom-clobbering-lab/webapp.pid

echo "==> Starting WAF VIP on :8780"
(cd "$ROOT/app/waf-proxy" && PORT=8780 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3700 node server.js >/tmp/dom-clobbering-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/dom-clobbering-lab/waf-proxy.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3700/health >/dev/null && curl -sf http://127.0.0.1:8780/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "HarborNotes:     http://127.0.0.1:3700/workbench"
echo "WAF VIP:         http://127.0.0.1:8780/workbench"
echo "WAF Classic API: http://127.0.0.1:4581"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
