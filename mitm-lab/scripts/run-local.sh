#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4577"
export AWS_PAGER=""

mkdir -p /tmp/mitm-lab
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

stop_pid /tmp/mitm-lab/webapp.pid
stop_pid /tmp/mitm-lab/mitm.pid
stop_pid /tmp/mitm-lab/waf-proxy.pid
stop_pid /tmp/mitm-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4577"
PORT=4577 node "$ROOT/waf/classic-api/server.js" >/tmp/mitm-lab/waf-api.log 2>&1 &
echo $! >/tmp/mitm-lab/waf-api.pid

echo "==> Starting Clearwire Bank on :3500"
(cd "$ROOT/app" && PORT=3500 node server.js >/tmp/mitm-lab/webapp.log 2>&1) &
echo $! >/tmp/mitm-lab/webapp.pid

echo "==> Starting MitM hotspot on :3580"
(cd "$ROOT/app/mitm-proxy" && PORT=3580 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3500 node server.js >/tmp/mitm-lab/mitm.log 2>&1) &
echo $! >/tmp/mitm-lab/mitm.pid

echo "==> Starting WAF VIP on :8580"
(cd "$ROOT/app/waf-proxy" && PORT=8580 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3500 node server.js >/tmp/mitm-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/mitm-lab/waf-proxy.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3500/health >/dev/null \
    && curl -sf http://127.0.0.1:3580/health >/dev/null \
    && curl -sf http://127.0.0.1:8580/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "Bank origin:     http://localhost:3500"
echo "MitM hotspot:    http://localhost:3580   (victim entry)"
echo "Attacker UI:     http://localhost:3580/_mitm/"
echo "WAF VIP:         http://localhost:8580"
echo "WAF Classic API: http://localhost:4577"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
