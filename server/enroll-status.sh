#!/usr/bin/env bash
# Enrollment status. Prints window state, cert pin, enrollment count.
# No secrets printed (key prefixes only, never PSKs).
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

NOW="$(date +%s)"
if [ -f "$WG_DIR/.enroll-window" ]; then
  EXPIRY="$(cat "$WG_DIR/.enroll-window" 2>/dev/null || echo 0)"
  LEFT=$(( (EXPIRY - NOW) / 60 ))
  if [ "$NOW" -lt "$EXPIRY" ]; then
    echo "[ok] window OPEN (~${LEFT}m left)"
  else
    echo "[FAIL] window EXPIRED (run ./vpn enroll-disarm to clean up)"
  fi
else
  echo "[ok] window CLOSED"
fi

if systemctl is-active --quiet privatewire-enroll.service 2>/dev/null; then
  echo "[ok] privatewire-enroll.service active"
else
  echo "-- privatewire-enroll.service not running"
fi

if [ -f "$WG_DIR/enroll-cert.pem" ]; then
  PIN="$(openssl x509 -in "$WG_DIR/enroll-cert.pem" -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null | openssl base64 -A 2>/dev/null || true)"
  echo "-- cert pin: ${PIN:-unreadable}"
  openssl x509 -in "$WG_DIR/enroll-cert.pem" -noout -dates 2>/dev/null | sed 's/^/-- /' || true
else
  echo "-- no enrollment cert yet (created by ./vpn enroll-arm)"
fi

N="$(ls "$WG_DIR/clients/"*.enrolled 2>/dev/null | wc -l | tr -d ' ')"
echo "-- enrolled devices on record: $N"
