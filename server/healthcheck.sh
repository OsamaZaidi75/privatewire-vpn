#!/usr/bin/env bash
# Tunnel health check for cron/systemd timers. Quiet on success.
# Verifies: interface up, at least the service handshake-able, forwarding, NAT, egress.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

ERRS=()
ip link show wg0 >/dev/null 2>&1 || ERRS+=("wg0 down")
systemctl is-active --quiet wg-quick@wg0 2>/dev/null || ERRS+=("service inactive")
[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] || ERRS+=("forwarding off")
iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE || ERRS+=("NAT missing")
timeout 8 curl -fsS -o /dev/null https://ipv4.icanhazip.com 2>/dev/null || ERRS+=("no egress")

if [ "${#ERRS[@]}" -gt 0 ]; then
  printf '[privatewire][health] UNHEALTHY: %s\n' "${ERRS[*]}" >&2
  exit 1
fi
exit 0
