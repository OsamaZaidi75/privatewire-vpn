#!/usr/bin/env bash
# Open an owner-armed enrollment window for PrivateWire multi-user setup.
# Usage: enroll-arm.sh [MINUTES]   (default 15, max 120)
#
# Effects: ensures the self-signed enrollment cert exists, writes the window
# expiry file, opens TCP 8443 in UFW, (re)starts privatewire-enroll.service,
# and prints the enrollment code (SECRET-equivalent during the window: anyone
# holding it can register a peer while the window is open — share it only
# with the device owner, then ./vpn enroll-disarm).
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
check_cmd openssl
check_cmd python3
check_cmd systemctl

MINUTES="${1:-15}"
case "$MINUTES" in
  ''|*[!0-9]*) die "usage: $0 [MINUTES (1-120)]" ;;
esac
[ "$MINUTES" -ge 1 ] && [ "$MINUTES" -le 120 ] || die "window must be 1-120 minutes"

# Env is optional: privatewire.env may not exist on minimal deploys.
if [ -f "$PW_ENV_FILE" ]; then
  set -a; . "$PW_ENV_FILE"; set +a
fi
ENROLL_PORT="${ENROLL_PORT:-8443}"
ENROLL_BIND="${ENROLL_BIND:-0.0.0.0}"
ENROLL_BUDGET="${ENROLL_BUDGET:-25}"
ENDPOINT_HOST="${ENROLL_ENDPOINT_HOST:-${SERVER_PUBLIC_IP:-}}"
ENDPOINT_PORT="${WIREGUARD_PORT:-51820}"
ENROLL_DNS="${ENROLL_DNS:-${DNS_SERVER:-}}"
[ -n "$ENDPOINT_HOST" ] || die "set SERVER_PUBLIC_IP in $PW_ENV_FILE or ENROLL_ENDPOINT_HOST"
[ -f "$WG_DIR/wg0.conf" ] || die "no $WG_DIR/wg0.conf — run deploy-server.sh first"

CERT="$WG_DIR/enroll-cert.pem"
KEY="$WG_DIR/enroll-key.pem"
umask 077
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  # Strict IPv4 check: a malformed host must never reach openssl (it would
  # either fail obscurely or mint a cert with a junk SAN).
  SAN_ARG=""
  if printf '%s' "$ENDPOINT_HOST" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
    SAN_ARG=" -addext subjectAltName=IP:$ENDPOINT_HOST"
  fi
  # shellcheck disable=SC2086
  openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
    -days 825 -nodes -subj '/CN=PrivateWire-Enrollment' $SAN_ARG
  chmod 600 "$KEY"; chmod 644 "$CERT"
  log "generated self-signed enrollment cert (825d)"
fi

NOW="$(date +%s)"
EXPIRY=$((NOW + MINUTES * 60))
printf '%s\n' "$EXPIRY" > "$WG_DIR/.enroll-window"
chmod 600 "$WG_DIR/.enroll-window"

# SPKI pin (RFC 7469): sha256 of the DER-encoded SubjectPublicKeyInfo.
PIN="$(openssl x509 -in "$CERT" -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | openssl base64 -A)"

# Open TCP $ENROLL_PORT for the window. Prefers UFW; falls back to a
# temporary tagged iptables rule (removed by enroll-disarm); warns if neither
# exists, since the owner must then open the port (and any cloud firewall).
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${ENROLL_PORT}/tcp" comment 'PrivateWire enrollment (temporary)' || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$ENROLL_PORT" \
    -m comment --comment 'privatewire-enroll' -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$ENROLL_PORT" \
      -m comment --comment 'privatewire-enroll' -j ACCEPT
else
  warn "no ufw/iptables found — open TCP $ENROLL_PORT yourself (plus any cloud firewall) or enrollment is unreachable"
fi

UNIT="/etc/systemd/system/privatewire-enroll.service"
sed -e "s|@SERVER_PY@|$PW_ROOT/enroll-server.py|g" \
    -e "s|@WG_DIR@|$WG_DIR|g" \
    -e "s|@BIND@|$ENROLL_BIND|g" \
    -e "s|@PORT@|$ENROLL_PORT|g" \
    -e "s|@CERT@|$CERT|g" \
    -e "s|@KEY@|$KEY|g" \
    -e "s|@ENDPOINT_HOST@|$ENDPOINT_HOST|g" \
    -e "s|@ENDPOINT_PORT@|$ENDPOINT_PORT|g" \
    -e "s|@DNS@|$ENROLL_DNS|g" \
    -e "s|@BUDGET@|$ENROLL_BUDGET|g" \
    -e "s|@OPEN_FLAG@||g" \
    "$PW_ROOT/templates/privatewire-enroll.service.tpl" > "$UNIT"
systemctl daemon-reload
systemctl restart privatewire-enroll.service
sleep 1
systemctl is-active --quiet privatewire-enroll.service \
  || die "enroll service failed to start (journalctl -u privatewire-enroll)"

CODE="pw-enroll://${ENDPOINT_HOST}:${ENROLL_PORT}#${PIN}"
echo
log "enrollment window OPEN for ${MINUTES}m (until $(date -d "@$EXPIRY" -u '+%H:%M UTC' 2>/dev/null || date -r "$EXPIRY" -u '+%H:%M UTC'))"
echo "  enrollment code (share with the device owner only):"
echo "  $CODE"
if command -v qrencode >/dev/null 2>&1; then
  echo; qrencode -t ansiutf8 <<<"$CODE"
fi
echo
log "when done: ./vpn enroll-disarm   (also check your cloud firewall for TCP $ENROLL_PORT)"
