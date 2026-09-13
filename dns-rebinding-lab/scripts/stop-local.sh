#!/usr/bin/env bash
set -euo pipefail
for f in /tmp/dns-rebinding-lab/*.pid; do
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
for port in 3900 3998 3999 8980 4585 5354 5355 5356; do
  kill_port "$port"
done
echo "Stopped local DNS rebinding lab processes"
