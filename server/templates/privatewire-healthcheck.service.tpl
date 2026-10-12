[Unit]
Description=PrivateWire tunnel health check
After=network-online.target wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/opt/privatewire/server/healthcheck.sh
NoNewPrivileges=true
PrivateTmp=true
# NOTE: healthcheck.sh contains no secrets; safe to run confined.
