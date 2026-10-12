#!/usr/bin/env bash
# Print a client .conf to stdout. SECRET OUTPUT: redirect to a file, do not paste into logs.
# Usage: show-config.sh NAME
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

NAME="${1:-}"; [ -n "$NAME" ] || die "usage: $0 NAME"
# Enrolled devices hold their private key on-device: there is no full
# server-side config to print (their .enrolled record is peer metadata only).
if [ ! -f "$CLIENTS_DIR/$NAME.conf" ]; then
  [ -f "$CLIENTS_DIR/$NAME.enrolled" ] \
    && die "enrolled device '$NAME': private key lives on the device — nothing to show server-side"
  die "unknown client '$NAME'"
fi
[ "$(stat -c %a "$CLIENTS_DIR/$NAME.conf" 2>/dev/null || stat -f %Lp "$CLIENTS_DIR/$NAME.conf")" = "600" ] \
  || warn "unexpected permissions on $NAME.conf (expected 600)"
cat "$CLIENTS_DIR/$NAME.conf"
