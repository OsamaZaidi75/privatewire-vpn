#!/usr/bin/env bash
# PERMANENT open registrar for the zero-touch friends build.
#
# ACCEPTED RISK (owner-approved): after this, ANYONE holding the APK can
# register a WireGuard peer, with no code and no window. Per-IP rate caps
# still apply. The device private key still never leaves the phone; the
# server still assigns IPs and issues per-device PSKs.
#
# Effects: ensures the self-signed cert, enables+starts
# privatewire-enroll.service at boot (--open-registrar), opens TCP 8443
# (UFW persistent rule, else tagged iptables rule + ExecStartPre re-add).
# Revert with: ./vpn enroll-disarm  (stops, disables, closes the port)
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
check_cmd openssl
check_cmd python3
check_cmd systemctl

if [ -f "$PW_ENV_FILE" ]; then
  set -a; . "$PW_ENV_FILE"; set +a
fi
ENROLL_PORT="${ENROLL_PORT:-8443}"
ENROLL_BIND="${ENROLL_BIND:-0.0.0.0}"
ENDPOINT_HOST="${ENROLL_ENDPOINT_HOST:-${SERVER_PUBLIC_IP:-}}"
ENDPOINT_PORT="${WIREGUARD_PORT:-51820}"
ENROLL_DNS="${ENROLL_DNS:-${DNS_SERVER:-}}"
[ -n "$ENDPOINT_HOST" ] || die "set SERVER_PUBLIC_IP in $PW_ENV_FILE or ENROLL_ENDPOINT_HOST"
[ -f "$WG_DIR/wg0.conf" ] || die "no $WG_DIR/wg0.conf — run deploy-server.sh first"

cat <<'EOF'
[privatewire][WARN] opening a PERMANENT registrar: anyone with the APK may enroll.
[privatewire][WARN] Owner accepted this tradeoff for the friends build. Revert: ./vpn enroll-disarm
EOF

CERT="$WG_DIR/enroll-cert.pem"
KEY="$WG_DIR/enroll-key.pem"
umask 077
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
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

# No window file in open mode: the service flag is the switch.
rm -f "$WG_DIR/.enroll-window"

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${ENROLL_PORT}/tcp" comment 'PrivateWire enrollment (open registrar)' || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$ENROLL_PORT" \
    -m comment --comment 'privatewire-enroll' -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$ENROLL_PORT" \
      -m comment --comment 'privatewire-enroll' -j ACCEPT
else
  warn "no ufw/iptables found — open TCP $ENROLL_PORT yourself (plus any cloud firewall)"
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
    -e "s|@BUDGET@|${ENROLL_BUDGET:-25}|g" \
    -e "s|@OPEN_FLAG@|--open-registrar|g" \
    "$PW_ROOT/templates/privatewire-enroll.service.tpl" > "$UNIT"
systemctl daemon-reload
systemctl enable privatewire-enroll.service >/dev/null
systemctl restart privatewire-enroll.service
sleep 1
systemctl is-active --quiet privatewire-enroll.service \
  || die "enroll service failed to start (journalctl -u privatewire-enroll)"

log "open registrar LIVE on TCP $ENROLL_PORT (enabled at boot)"
log "revert anytime: ./vpn enroll-disarm"
