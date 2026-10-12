#!/usr/bin/env bash
# Diagnostics: WireGuard status, forwarding, NAT, connectivity. No secrets printed.
# Usage: status.sh [--self-check]  (--self-check exits non-zero on failure)
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

SELFCHECK=0; [ "${1:-}" = "--self-check" ] && SELFCHECK=1
FAIL=0
ok()   { echo "[ok] $*"; }
bad()  { echo "[FAIL] $*"; FAIL=1; }

command -v wg >/dev/null 2>&1 || { bad "wireguard-tools not installed"; }
command -v jq >/dev/null 2>&1 || true

if ip link show wg0 >/dev/null 2>&1; then ok "interface wg0 exists"; else bad "interface wg0 missing"; fi
if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then ok "wg-quick@wg0 active"; else bad "wg-quick@wg0 not active"; fi
systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null && ok "autostart enabled" || bad "autostart NOT enabled"

if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then ok "IPv4 forwarding on"; else bad "IPv4 forwarding OFF"; fi

if iptables -t nat -C POSTROUTING -o "${SERVER_PRIVATE_INTERFACE:-}" -j MASQUERADE 2>/dev/null \
   || iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
  ok "NAT MASQUERADE present"
else
  bad "NAT MASQUERADE missing"
fi

if ufw status 2>/dev/null | grep -qi active; then ok "firewall active"; else bad "firewall not active"; fi

echo "--- peers (public key prefix + last handshake only; no secrets) ---"
wg show wg0 peers 2>/dev/null | cut -c1-12 | sed 's/^/peer: /' || bad "wg show failed"
wg show wg0 latest-handshakes 2>/dev/null | awk '{print "handshake: " substr($1,1,12) " " $2 "s-ago"}' || true

echo "--- outbound connectivity ---"
if timeout 8 curl -fsS -o /dev/null https://ipv4.icanhazip.com 2>/dev/null; then ok "internet reachable"; else bad "no internet"; fi

[ "$SELFCHECK" = "1" ] && [ "$FAIL" -ne 0 ] && die "self-check FAILED"
[ "$FAIL" -ne 0 ] && warn "some checks failed — see docs/troubleshooting.md"
exit "$FAIL"
