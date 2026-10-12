#!/usr/bin/env bash
# Logic tests for server IP allocation / naming / revocation helpers.
# Runs WITHOUT root and WITHOUT wireguard — stubs environment in a temp dir.
set -euo pipefail

T="$(dirname "$0")/.scratch"; rm -rf "$T"; mkdir -p "$T"; trap 'rm -rf "$T"' EXIT
export WG_DIR="$T/wg" PW_ENV_FILE="$T/privatewire.env"
mkdir -p "$WG_DIR/clients"

cat > "$PW_ENV_FILE" <<'EOF'
SERVER_PUBLIC_IP=203.0.113.10
SERVER_PRIVATE_INTERFACE=eth0
WIREGUARD_PORT=51820
WIREGUARD_NETWORK=10.8.0.0/24
DNS_SERVER=10.8.0.1
EOF

# shellcheck disable=SC1091
. "$(dirname "$0")/../lib/common.sh"

PASS=0; FAIL=0
check() { # $1 desc, rest = command
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "ok: $desc";
  else FAIL=$((FAIL+1)); echo "FAIL: $desc"; fi
}
check_not() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then FAIL=$((FAIL+1)); echo "FAIL(should reject): $desc";
  else PASS=$((PASS+1)); echo "ok: $desc"; fi
}

load_env
[ "$SERVER_VPN_IP" = "10.8.0.1" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: server ip"; }

# naming
check "accept simple name" valid_client_name phone
check "accept laptop-2_x" valid_client_name laptop-2_x
check_not "reject empty" valid_client_name ""
check_not "reject spaces" valid_client_name "my phone"
check_not "reject path traversal" valid_client_name "../etc"
check_not "reject semicolon" valid_client_name 'a;b'

# allocation on empty ledger
touch "$ALLOC_FILE"
[ "$(next_client_ip)" = "10.8.0.2" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: first ip"; }

# allocation skips taken + never duplicates
printf 'phone 10.8.0.2/32\nlaptop 10.8.0.3/32\n' > "$ALLOC_FILE"
[ "$(next_client_ip)" = "10.8.0.4" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: next ip skips taken"; }

# gap reuse (.2 freed -> reused)
printf 'laptop 10.8.0.3/32\n' > "$ALLOC_FILE"
[ "$(next_client_ip)" = "10.8.0.2" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL: gap reuse"; }

# full subnet refuses
: > "$ALLOC_FILE"
for o in $(seq 2 254); do echo "c$o 10.8.0.$o/32" >> "$ALLOC_FILE"; done
check_not "refuse when subnet full" next_client_ip

# duplicate detection against live config
: > "$ALLOC_FILE"
printf '[Interface]\nAddress = 10.8.0.1/24\n\n# client: phone (10.8.0.2)\n[Peer]\nAllowedIPs = 10.8.0.2/32\n' > "$WG_DIR/wg0.conf"
check "detect taken ip" client_ip_taken 10.8.0.2
check_not "free ip not taken" client_ip_taken 10.8.0.9

echo "--- pass=$PASS fail=$FAIL ---"
[ "$FAIL" -eq 0 ]
