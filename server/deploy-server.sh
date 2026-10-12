#!/usr/bin/env bash
# Automated PrivateWire server deployment. Idempotent and provider-neutral.
#
#  1. detect distro, 2. install packages, 3. configure WireGuard,
#  4. firewall, 5. forwarding, 6. NAT, 7. server keys,
#  8. start WireGuard, 9. verify tunnel, 10. print first-client instructions.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
load_env
check_cmd wg

log "=== 1-2. distro check + packages ==="
"$PW_ROOT/install.sh"

log "=== 3-7. server keys + wg0.conf ==="
umask 077
[ -f "$WG_DIR/server_private.key" ] || { wg genkey | tee "$WG_DIR/server_private.key" >/dev/null; log "generated server keypair"; }
chmod 600 "$WG_DIR/server_private.key"
wg pubkey < "$WG_DIR/server_private.key" > "$WG_DIR/server_public.key"
chmod 644 "$WG_DIR/server_public.key"
SERVER_PRIV="$(cat "$WG_DIR/server_private.key")"
SERVER_PUB="$(cat "$WG_DIR/server_public.key")"

mkdir -p "$CLIENTS_DIR"
touch "$ALLOC_FILE"; chmod 600 "$ALLOC_FILE"

if [ ! -f "$WG_DIR/wg0.conf" ]; then
  cat > "$WG_DIR/wg0.conf" <<EOF
# PrivateWire server. Managed by server/vpn — do not hand-edit [Peer] blocks.
[Interface]
PrivateKey = $SERVER_PRIV
Address = $SERVER_VPN_IP/24
ListenPort = $WIREGUARD_PORT
SaveConfig = false
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PRIVATE_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PRIVATE_INTERFACE -j MASQUERADE
EOF
  chmod 600 "$WG_DIR/wg0.conf"
  log "wrote $WG_DIR/wg0.conf"
else
  log "keeping existing $WG_DIR/wg0.conf (client peers preserved)"
fi

log "=== 4. firewall (UFW): allow ${WIREGUARD_PORT}/udp + existing SSH only ==="
ufw allow "${WIREGUARD_PORT}/udp" comment 'PrivateWire WireGuard' || true
# Do NOT touch SSH rules: never close an existing session, never open new ones.
ufw --force enable || true
ufw status | head -n20

log "=== 5. IP forwarding ==="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null \
  || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p >/dev/null 2>&1 || true

log "=== 8. start WireGuard (autostart enabled) ==="
systemctl enable "wg-quick@wg0" >/dev/null
if systemctl is-active --quiet "wg-quick@wg0"; then
  systemctl reload-or-restart "wg-quick@wg0"
else
  systemctl start "wg-quick@wg0"
fi
sleep 2

log "=== 9. verify ==="
"$PW_ROOT/status.sh" --self-check

echo
log "=== 10. server public key (safe to share) ==="
echo "$SERVER_PUB"
echo
log "create your first Android client with:"
echo "  ./vpn add-client phone"
echo "  ./vpn qr phone"
