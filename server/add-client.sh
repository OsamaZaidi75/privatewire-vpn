#!/usr/bin/env bash
# Add a WireGuard client: keys, IP allocation, peer block, client .conf.
# Usage: add-client.sh NAME [--split]
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
load_env
check_cmd wg

NAME="${1:-}"; [ -n "$NAME" ] || die "usage: $0 NAME [--split]"
MODE="${2:-full}"
valid_client_name "$NAME" || die "bad client name '$NAME' (a-z, 0-9, _,-; max 32)"
[ -f "$CLIENTS_DIR/$NAME.conf" ] && die "client '$NAME' already exists"
[ -f "$WG_DIR/wg0.conf" ] || die "no $WG_DIR/wg0.conf — run deploy-server.sh first"

IP="$(next_client_ip)" || die "subnet $WIREGUARD_NETWORK is full"
client_ip_taken "$IP" && die "IP $IP already present in wg0.conf (stale alloc?)"

umask 077
CLIENT_PRIV="$(wg genkey)"
CLIENT_PUB="$(printf '%s' "$CLIENT_PRIV" | wg pubkey)"
PSK="$(wg genpsk)"
SERVER_PUB="$(server_public_key)"

case "$MODE" in
  --split) ALLOWED="10.8.0.0/24" ;;   # split-tunnel: only VPN subnet routed
  *)       ALLOWED="0.0.0.0/0" ;;     # full-tunnel default
esac

# Peer block appended atomically, then live-applied without dropping others.
PEER_TMP="$(mktemp)"
cat > "$PEER_TMP" <<EOF

# client: $NAME ($IP)
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PSK
AllowedIPs = $IP/32
EOF
cat "$PEER_TMP" >> "$WG_DIR/wg0.conf"
rm -f "$PEER_TMP"
chmod 600 "$WG_DIR/wg0.conf"

cat > "$CLIENTS_DIR/$NAME.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $IP/32
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
AllowedIPs = $ALLOWED
Endpoint = ${SERVER_PUBLIC_IP}:${WIREGUARD_PORT}
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENTS_DIR/$NAME.conf"
printf '%s %s/32\n' "$NAME" "$IP" >> "$ALLOC_FILE"

# Live-apply: full reload only if interface already up; never leave it down.
if ip link show wg0 >/dev/null 2>&1; then
  wg syncconf wg0 <(wg-quick strip "$WG_DIR/wg0.conf") || systemctl reload-or-restart wg-quick@wg0
else
  systemctl start wg-quick@wg0
fi

log "added client '$NAME' ($IP, mode: ${MODE#--})"
log "transfer the config securely: ./vpn qr $NAME  (or show-config)"
