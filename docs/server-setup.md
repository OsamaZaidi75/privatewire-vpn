# Server setup (Ubuntu 22.04/24.04, Debian 11/12)

Provider-neutral: any VM with a public IPv4, root SSH, and a kernel that
supports WireGuard (all listed distros do).

## 1. Prepare the VM

- 1 vCPU / 512 MB RAM is plenty for personal use.
- Open firewall for **your SSH** and **UDP 51820** (or your `WIREGUARD_PORT`).
- Nothing else needs to be reachable.

## 2. Deploy

```sh
# on the server, as root
git clone <your-private-repo-url> privatewire
cd privatewire/server
cp privatewire.env.example privatewire.env
nano privatewire.env   # set SERVER_PUBLIC_IP at minimum
chmod +x install.sh deploy-server.sh vpn *.sh
./deploy-server.sh
```

What it does: distro check → installs `wireguard wireguard-tools iptables
ufw qrencode curl` → generates server keypair (`wg genkey`, 0600) →
writes `/etc/wireguard/wg0.conf` → UFW allow `$PORT/udp` (SSH rules
untouched) → enables IPv4 forwarding → enables + starts `wg-quick@wg0` →
self-check → prints server public key.

## 3. Client lifecycle

```sh
./vpn add-client phone            # full-tunnel (AllowedIPs 0.0.0.0/0)
./vpn add-client laptop --split   # split-tunnel (VPN subnet only)
./vpn list-clients
./vpn show-config phone           # SECRET — redirect to file, never log
./vpn qr phone                    # SECRET — scan from the app
./vpn remove-client phone         # revokes immediately (wg set peer remove)
./vpn status                      # diagnostics, no secrets
```

Details:

- IPs allocate `.2`→`.254` from `WIREGUARD_NETWORK`; duplicates impossible
  (ledger + live-config double-check).
- Adding applies live via `wg syncconf` (other peers undisturbed); removal
  via `wg set peer remove`.
- `SaveConfig = false`: `/etc/wireguard/wg0.conf` is the source of truth.

## 4. Health monitoring (optional)

```sh
cp templates/privatewire-healthcheck.{service,timer}.tpl \
   /etc/systemd/system/privatewire-healthcheck.service   # edit ExecStart path first
systemctl daemon-reload
systemctl enable --now privatewire-healthcheck.timer
```

## 5. IPv6 (optional)

Leave `WIREGUARD_NETWORK_V6` empty (default): IPv4-only server. Then either
disable IPv6 on clients or accept that v6 traffic bypasses the tunnel —
documented in [security](security.md). For full v6 support, set the ULA
prefix and add `::/0` to client AllowedIPs.

## 6. Free-tier pointers (verify current terms yourself)

- Oracle Cloud "Always Free": 2× ARM VMs (up to 4 OCPU/24 GB total),
  10 TB/month egress at the time of writing — generous but account needs a
  card, idle resources may be reclaimed, regions vary.
- Google Cloud free trial + e2-micro monthly allowance; AWS t2/t3-micro
  750 h/month for 12 months; Azure B1s 750 h/month.
- All have bandwidth caps/overage billing and eligibility rules — read the
  provider's current page before deploying; this project assumes nothing.
