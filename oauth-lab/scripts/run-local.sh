#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4587"
export AWS_PAGER=""

mkdir -p /tmp/oauth-lab
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

kill_port() {
  local port="$1"
  local pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
    return
  fi
  for pid in $pids; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
}

stop_pid /tmp/oauth-lab/webapp.pid
stop_pid /tmp/oauth-lab/waf-proxy.pid
stop_pid /tmp/oauth-lab/waf-api.pid
for port in 4000 4098 4099 9080 4587; do
  kill_port "$port"
done
sleep 0.4

echo "==> Starting WAF Classic API on :4587"
PORT=4587 node "$ROOT/waf/classic-api/server.js" >/tmp/oauth-lab/waf-api.log 2>&1 &
echo $! >/tmp/oauth-lab/waf-api.pid

echo "==> Starting HarborNotes + HarborSocial + workbench"
(cd "$ROOT/app" && NOTES_PORT=4000 IDP_PORT=4098 WORKBENCH_PORT=4099 node server.js >/tmp/oauth-lab/webapp.log 2>&1) &
echo $! >/tmp/oauth-lab/webapp.pid

echo "==> Starting WAF proxy on :9080"
(cd "$ROOT/app/waf-proxy" && PORT=9080 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=4000 IDP_HOST=127.0.0.1 IDP_PORT=4098 node server.js >/tmp/oauth-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/oauth-lab/waf-proxy.pid

for _ in $(seq 1 50); do
  if curl -sf http://127.0.0.1:4000/health >/dev/null \
    && curl -sf http://127.0.0.1:4098/health >/dev/null \
    && curl -sf http://127.0.0.1:4099/health >/dev/null \
    && curl -sf http://127.0.0.1:9080/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "HarborNotes:     http://127.0.0.1:4000"
echo "HarborSocial:    http://127.0.0.1:4098"
echo "Workbench:       http://127.0.0.1:4099"
echo "WAF gate:        http://127.0.0.1:9080"
echo "WAF Classic API: http://127.0.0.1:4587"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
