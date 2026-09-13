#!/usr/bin/env bash
set -euo pipefail
for f in /tmp/oauth-lab/*.pid; do
  [[ -f "$f" ]] || continue
  pid="$(cat "$f" || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
done
kill_port() {
  local port="$1"
  local pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  fi
  for pid in $pids; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
}
for port in 4000 4098 4099 9080 4587; do
  kill_port "$port"
done
echo "Stopped local OAuth lab processes"
