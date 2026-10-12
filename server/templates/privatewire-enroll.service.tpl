# systemd unit for the PrivateWire enrollment endpoint.
# Rendered by enroll-arm.sh (@TOKENS@ substituted); never enabled at boot —
# it only runs inside an owner-armed window and exits when the window lapses.
[Unit]
Description=PrivateWire enrollment endpoint (owner-armed window only)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
# Re-add the tagged TCP allow rule on (re)start: ufw rules persist on their
# own, but raw-iptables rules do not survive reboot — without this a
# boot-enabled service would listen behind a closed port.
ExecStartPre=/bin/sh -c 'iptables -C INPUT -p tcp --dport @PORT@ -m comment --comment privatewire-enroll -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport @PORT@ -m comment --comment privatewire-enroll -j ACCEPT 2>/dev/null || true'
ExecStart=/usr/bin/python3 @SERVER_PY@ --bind @BIND@ --port @PORT@ \
  --wg-dir @WG_DIR@ --cert @CERT@ --key @KEY@ \
  --endpoint-host @ENDPOINT_HOST@ --endpoint-port @ENDPOINT_PORT@ \
  --dns @DNS@ --budget @BUDGET@ @OPEN_FLAG@
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
