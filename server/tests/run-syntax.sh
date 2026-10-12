#!/usr/bin/env bash
# Syntax-check every server script. Exit non-zero on any failure.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FAIL=0
while IFS= read -r f; do
  if bash -n "$ROOT/$f"; then
    echo "SYNTAX OK: $f"
  else
    echo "SYNTAX FAIL: $f"
    FAIL=1
  fi
done <<'EOF'
server/install.sh
server/deploy-server.sh
server/vpn
server/add-client.sh
server/remove-client.sh
server/list-clients.sh
server/show-config.sh
server/qr.sh
server/status.sh
server/healthcheck.sh
server/enroll-arm.sh
server/enroll-open.sh
server/enroll-disarm.sh
server/enroll-status.sh
server/lib/common.sh
server/tests/test-alloc.sh
server/tests/run-syntax.sh
EOF

if command -v python3 >/dev/null 2>&1; then
  for py in server/enroll-server.py server/tests/test-enroll.py; do
    if python3 -m py_compile "$ROOT/$py"; then
      echo "SYNTAX OK: $py"
    else
      echo "SYNTAX FAIL: $py"
      FAIL=1
    fi
  done
else
  echo "SKIP: python3 missing (no enroll-server.py check)"
fi
exit "$FAIL"
