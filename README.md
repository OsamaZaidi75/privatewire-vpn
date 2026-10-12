# PrivateWire — personal WireGuard VPN

A complete personal VPN system: Ubuntu/Debian WireGuard server +
modern Android client ("PrivateWire", `com.privatewire.vpn`).

- [README](README.md) (this repo root is `PrivateWire/`)
- [Architecture](docs/architecture.md)
- [Server setup](docs/server-setup.md) · [Android setup](docs/android-setup.md)
- [Security](docs/security.md) · [Troubleshooting](docs/troubleshooting.md)
- [Multi-user enrollment](docs/enrollment.md)
- [Testing](docs/TESTING.md) · [Free-tier notes](docs/free-tier.md)

> Legitimate personal/private use only. Uses official WireGuard —
> no custom VPN protocol, no custom cryptography.

## Quick start

**1. Deploy the server** (fresh Ubuntu 22.04/24.04 or Debian 11/12 VM,
root shell):

```sh
git clone <your-private-repo-url> privatewire && cd privatewire/server
cp privatewire.env.example privatewire.env
# edit privatewire.env: SERVER_PUBLIC_IP, WIREGUARD_PORT, WIREGUARD_NETWORK, DNS_SERVER
./deploy-server.sh
```

**2. Create the first Android client:**

```sh
./vpn add-client phone
./vpn qr phone        # scan from the app, or:
./vpn show-config phone
```

**3. Install the app:** copy
`android/app/build/outputs/apk/debug/PrivateWire-debug.apk` to the phone,
open it to install, then import the config and tap **Connect**.

See [docs/server-setup.md](docs/server-setup.md) and
[docs/android-setup.md](docs/android-setup.md) for details.

## Layout

```text
PrivateWire/
├── android/   # Kotlin app (com.privatewire.vpn)
├── server/    # provisioning + client-management scripts
├── docs/      # guides and references
├── .gitignore
└── README.md
```

## Security rules enforced by this project

- WireGuard only; official implementations on both ends.
- Keys generated with `wg genkey` (CSPRNG) on the machine that owns them.
- Private keys `chmod 600`, never logged, never committed.
- Server exposes one UDP port; no extra listening services.
- No traffic-content logging, no analytics.
