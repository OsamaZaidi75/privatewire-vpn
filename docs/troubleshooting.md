# Troubleshooting

## Server

| Symptom | Check |
|---|---|
| `./vpn status` FAILs | Run each section; most common: forwarding off (`sysctl net.ipv4.ip_forward`), NAT missing (re-run `deploy-server.sh` — idempotent), UFW blocking UDP |
| Handshake never completes | `SERVER_PUBLIC_IP` wrong / cloud firewall blocks UDP port / client Endpoint stale |
| Client gets no internet | NAT MASQUERADE missing; forwarding off; provider blocks forwarding |
| `add-client` says subnet full | /24 exhausted (253 clients) — use a bigger `WIREGUARD_NETWORK` on a fresh deploy |
| After reboot wg0 missing | `systemctl enable wg-quick@wg0`; check `journalctl -u wg-quick@wg0` (no secrets there) |
| Handshake never completes, `rx: 0 tx: 0`, endpoint `(none)` | Packets reach the NIC (tcpdump) but die in local INPUT: ensure an `ACCEPT udp --dport $PORT` rule sits **above** any REJECT-all, and persist it via `PostUp`/`PostDown` in `wg0.conf` (a hand-added rule is lost on reboot) |
| Tunnel is up but no internet | Check `iptables -L FORWARD`: the wg ACCEPTs must come **before** any REJECT-all (`PostUp` must use `-I`, not `-A`); also confirm a DNS resolver is reachable at the client's configured DNS (e.g. dnsmasq on the VPN gateway IP, bound to `wg0` only) |
| After reboot, tunnel works but DNS fails (`unknown host`) | Boot race: dnsmasq starts before `wg0` exists, so `listen-address=10.66.66.1` fails and the service stays dead. Fix with a drop-in `/etc/systemd/system/dnsmasq.service.d/after-wg.conf` containing `[Unit]` + `After=wg-quick@wg0.service` / `Wants=wg-quick@wg0.service` and `[Service]` + `Restart=on-failure` / `RestartSec=5`, then `daemon-reload` + `start dnsmasq`. Binding stays wg0-only. |

## Android

| Symptom | Check |
|---|---|
| "VPN permission denied" | Accept the system dialog; if checked "don't ask", re-enable in Settings → VPN |
| Stuck on "Connecting…" | Server unreachable (see above); after 30 s the app reports an error — read it |
| Drops on Wi-Fi ↔ mobile switch | Normal: auto-reconnect with backoff handles it; keep auto-reconnect on |
| Killed in background | Exempt PrivateWire from battery optimization; keep the notification visible |
| QR scan fails | Increase terminal font / brightness; or use `show-config` + file import |
| "Invalid configuration" on import | The app tells you which field; usually a truncated key from copy-paste |

## Never do this while debugging

- Do not paste full configs or keys into chats/issues/logs.
- Do not set `AllowedIPs` to empty to "test" — that routes nothing.
- Do not disable UFW to "test" — add the port rule instead.
