#!/usr/bin/env bash
# Shared helpers for PrivateWire server scripts.
# Logging policy: NEVER log private keys, full client configs, URLs, or packet contents.
set -euo pipefail

PW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PW_ENV_FILE="${PW_ENV_FILE:-$PW_ROOT/privatewire.env}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="$WG_DIR/clients"
ALLOC_FILE="$WG_DIR/.ip-alloc"

log()  { printf '[privatewire] %s\n' "$*"; }
warn() { printf '[privatewire][WARN] %s\n' "$*" >&2; }
die()  { printf '[privatewire][ERROR] %s\n' "$*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run as root (e.g. sudo $0)"
}

load_env() {
  [ -f "$PW_ENV_FILE" ] || die "missing $PW_ENV_FILE (copy privatewire.env.example first)"
  set -a
  # shellcheck disable=SC1090
  . "$PW_ENV_FILE"
  set +a
  : "${SERVER_PUBLIC_IP:?set SERVER_PUBLIC_IP in $PW_ENV_FILE}"
  : "${WIREGUARD_PORT:=51820}"
  : "${WIREGUARD_NETWORK:=10.8.0.0/24}"
  : "${DNS_SERVER:=10.8.0.1}"
  SERVER_PRIVATE_INTERFACE="${SERVER_PRIVATE_INTERFACE:-$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)}"
  [ -n "${SERVER_PRIVATE_INTERFACE:-}" ] || die "cannot detect outbound interface; set SERVER_PRIVATE_INTERFACE"
  NETWORK_BASE="${WIREGUARD_NETWORK%/*}"
  NETWORK_PREFIX="${WIREGUARD_NETWORK#*/}"
  SERVER_VPN_IP="${NETWORK_BASE%.*}.1"
}

valid_client_name() {
  case "$1" in
    ''|*[!a-zA-Z0-9_-]*) return 1 ;;
    *) [ "${#1}" -le 32 ] ;;
  esac
}

# Allocate the next free client IP (.2 .. .254). Refuses duplicates.
next_client_ip() {
  local octet used ip
  used="$(awk -F'[./]' '{print $4}' "$ALLOC_FILE" 2>/dev/null | sort -n | uniq)"
  for octet in $(seq 2 254); do
    if ! printf '%s\n' "$used" | grep -qx "$octet"; then
      echo "${NETWORK_BASE%.*}.$octet"
      return 0
    fi
  done
  return 1
}

client_ip_taken() { # $1 = ip
  grep -q -E "(^|[ .])$1(/32)?([ ,]|$)" "$WG_DIR/wg0.conf" 2>/dev/null
}

server_public_key() { cat "$WG_DIR/server_public.key"; }

check_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
