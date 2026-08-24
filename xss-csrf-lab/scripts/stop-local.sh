#!/usr/bin/env bash
set -euo pipefail
for f in /tmp/xss-csrf-lab/*.pid; do
  [[ -f "$f" ]] || continue
  pid="$(cat "$f" || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
done
echo "Stopped local XSS-CSRF lab processes"
