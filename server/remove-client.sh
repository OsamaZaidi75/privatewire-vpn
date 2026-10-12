#!/usr/bin/env bash
# Revoke a client: remove peer, free IP, delete client config.
# Usage: remove-client.sh NAME
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root
load_env

NAME="${1:-}"; [ -n "$NAME" ] || die "usage: $0 NAME"
# Enrolled devices keep their private key on-device: the server holds a
# .enrolled record instead of a full .conf. Both revoke the same way.
CLIENT_FILE="$CLIENTS_DIR/$NAME.conf"
[ -f "$CLIENT_FILE" ] || CLIENT_FILE="$CLIENTS_DIR/$NAME.enrolled"
[ -f "$CLIENT_FILE" ] || die "unknown client '$NAME' (see ./vpn list-clients)"

# Extract peer public key before deleting the client file.
PUB="$(awk '/PublicKey/ {print $3; exit}' "$CLIENT_FILE" 2>/dev/null || true)"

# Remove the "# client: NAME" comment + its [Peer] block only. Everything
# before the first comment (the [Interface] section) and all other blocks —
# commented or hand-added — are preserved. The removed block ends at the
# next blank line or EOF.
awk -v name="$NAME" '
  /^# client: / { skip = ($3 == name); if (!skip) print; next }
  skip && NF == 0 { skip = 0 }
  !skip { print }
  ' "$WG_DIR/wg0.conf" > "$WG_DIR/wg0.conf.tmp"
mv "$WG_DIR/wg0.conf.tmp" "$WG_DIR/wg0.conf"
chmod 600 "$WG_DIR/wg0.conf"

sed -i "/^$NAME /d" "$ALLOC_FILE" 2>/dev/null || true
rm -f "$CLIENTS_DIR/$NAME.conf" "$CLIENTS_DIR/$NAME.enrolled"

if ip link show wg0 >/dev/null 2>&1; then
  if [ -n "${PUB:-}" ]; then
    wg set wg0 peer "$PUB" remove || systemctl reload-or-restart wg-quick@wg0
  else
    systemctl reload-or-restart wg-quick@wg0
  fi
fi
log "revoked client '$NAME'"
