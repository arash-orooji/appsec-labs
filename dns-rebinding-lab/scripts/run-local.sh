#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL="http://127.0.0.1:4585"
export AWS_PAGER=""

mkdir -p /tmp/dns-rebinding-lab
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
    pids+=$'\n'"$(lsof -t -iUDP:"$port" 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
    fuser -k "${port}/udp" >/dev/null 2>&1 || true
    return
  fi
  for pid in $pids; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
}

stop_pid /tmp/dns-rebinding-lab/webapp.pid
stop_pid /tmp/dns-rebinding-lab/waf-proxy.pid
stop_pid /tmp/dns-rebinding-lab/waf-api.pid
for port in 3900 3998 3999 8980 4585 5354 5355 5356; do
  kill_port "$port"
done
sleep 0.4

echo "==> Starting WAF Classic API on :4585"
PORT=4585 node "$ROOT/waf/classic-api/server.js" >/tmp/dns-rebinding-lab/waf-api.log 2>&1 &
echo $! >/tmp/dns-rebinding-lab/waf-api.pid

echo "==> Starting HarborHome + DNS + gateway on :3900/:3998/:3999/:5354-5356"
(cd "$ROOT/app" && PORT=3900 node server.js >/tmp/dns-rebinding-lab/webapp.log 2>&1) &
echo $! >/tmp/dns-rebinding-lab/webapp.pid

echo "==> Starting WAF proxy on :8980"
(cd "$ROOT/app/waf-proxy" && PORT=8980 UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=3900 node server.js >/tmp/dns-rebinding-lab/waf-proxy.log 2>&1) &
echo $! >/tmp/dns-rebinding-lab/waf-proxy.pid

for _ in $(seq 1 50); do
  if curl -sf http://127.0.0.1:3900/health >/dev/null \
    && curl -sf http://127.0.0.1:3998/health >/dev/null \
    && curl -sf http://127.0.0.1:3999/health >/dev/null \
    && curl -sf http://127.0.0.1:8980/health >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "==> Creating WAF Classic WebACL"
bash "$ROOT/waf/setup-waf.sh"

echo ""
echo "HarborHome:      http://127.0.0.1:3900"
echo "Flip gateway:    http://127.0.0.1:3998"
echo "Workbench:       http://127.0.0.1:3999"
echo "WAF gate:        http://127.0.0.1:8980"
echo "WAF Classic API: http://127.0.0.1:4585"
echo "DNS raw:         127.0.0.1:5354"
echo "DNS perimeter:   127.0.0.1:5355  (drop RFC1918 + 127/8)"
echo "DNS strict:      127.0.0.1:5356  (also drop 0.0.0.0 + CNAME bypasses)"
echo ""
echo "Stop with: bash $ROOT/scripts/stop-local.sh"
