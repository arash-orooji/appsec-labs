#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4583"
export AWS_PAGER=""

mkdir -p /tmp/postmessage-lab
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

stop_pid /tmp/postmessage-lab/webapp.pid
stop_pid /tmp/postmessage-lab/attacker.pid
stop_pid /tmp/postmessage-lab/waf-proxy.pid
stop_pid /tmp/postmessage-lab/waf-api.pid

echo "==> Starting WAF Classic API on :4583"
PORT=4583 node "$ROOT/waf/classic-api/server.js" >/tmp/postmessage-lab/waf-api.log 2>&1 &
echo $! >/tmp/postmessage-lab/waf-api.pid

echo "==> Starting HarborLink on :3800"
(cd "$ROOT/app" && PORT=3800 node server.js >/tmp/postmessage-lab/webapp.log 2>&1) &
echo $! >/tmp/postmessage-lab/webapp.pid

echo "==> Starting attacker origin on :3899"
PORT=3899 node "$ROOT/app/attacker/server.js" >/tmp/postmessage-lab/attacker.log 2>&1 &
echo $! >/tmp/postmessage-lab/attacker.pid

echo "==> Starting WAF VIP on :8880"
(cd "$ROOT/app/waf-proxy" && PORT=8880 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3800 node server.js >/tmp/postmessage-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/postmessage-lab/waf-proxy.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:3800/health >/dev/null \
    && curl -sf http://127.0.0.1:3899/health >/dev/null \
    && curl -sf http://127.0.0.1:8880/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "HarborLink:      http://127.0.0.1:3800/workbench"
echo "Attacker:        http://127.0.0.1:3899"
echo "WAF VIP:         http://127.0.0.1:8880/workbench"
echo "WAF Classic API: http://127.0.0.1:4583"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
