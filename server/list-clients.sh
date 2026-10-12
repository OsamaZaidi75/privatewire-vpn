#!/usr/bin/env bash
# List clients. Prints names + IPs only (no secrets).
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

load_env 2>/dev/null || true
printf '%-20s %s\n' "CLIENT" "IP"
if [ -f "$ALLOC_FILE" ] && [ -s "$ALLOC_FILE" ]; then
  sort -t. -k4 -n "$ALLOC_FILE" | while read -r name ip; do printf '%-20s %s\n' "$name" "$ip"; done
else
  echo "(no clients yet — ./vpn add-client phone)"
fi
