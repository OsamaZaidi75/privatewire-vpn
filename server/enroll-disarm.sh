#!/usr/bin/env bash
# Close the enrollment window: stop the listener, close the firewall port,
# remove the window file. Idempotent — safe to run twice.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
if [ -f "$PW_ENV_FILE" ]; then
  set -a; . "$PW_ENV_FILE" 2>/dev/null; set +a
fi
ENROLL_PORT="${ENROLL_PORT:-8443}"

systemctl stop privatewire-enroll.service 2>/dev/null || true
systemctl disable privatewire-enroll.service 2>/dev/null || true
if command -v ufw >/dev/null 2>&1; then
  ufw delete allow "${ENROLL_PORT}/tcp" 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -D INPUT -p tcp --dport "${ENROLL_PORT}" \
    -m comment --comment 'privatewire-enroll' -j ACCEPT 2>/dev/null || true
fi
rm -f "$WG_DIR/.enroll-window"
log "enrollment window CLOSED (TCP $ENROLL_PORT shut)"
