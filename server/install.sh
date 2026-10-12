#!/usr/bin/env bash
# Install OS packages required by PrivateWire. Provider-neutral.
# Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12.
set -euo pipefail
. "$(dirname "$0")/lib/common.sh"

require_root

if [ -f /etc/os-release ]; then . /etc/os-release; else die "/etc/os-release missing"; fi
log "detected: ${PRETTY_NAME:-$ID $VERSION_ID}"
case "$ID" in
  ubuntu|debian) ;;
  *) die "unsupported distribution: $ID (need Ubuntu or Debian)" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  wireguard wireguard-tools iproute2 iptables ufw qrencode \
  curl ca-certificates systemd

command -v wg >/dev/null || die "wireguard-tools install failed"
log "packages installed (wg: $(wg --version 2>&1 | head -n1))"
