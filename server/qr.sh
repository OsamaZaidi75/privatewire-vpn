#!/usr/bin/env bash
# Render a client config as a QR code (ANSI, terminal). SECRET OUTPUT.
# Usage: qr.sh NAME — scan directly from the PrivateWire Android app.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

NAME="${1:-}"; [ -n "$NAME" ] || die "usage: $0 NAME"
[ -f "$CLIENTS_DIR/$NAME.conf" ] || die "unknown client '$NAME'"
check_cmd qrencode
# qrencode reads the raw .conf bytes: output is exactly the WireGuard config.
qrencode -t ansiutf8 < "$CLIENTS_DIR/$NAME.conf"
