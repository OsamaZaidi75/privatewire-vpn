# Architecture

```text
Android (PrivateWire app)                    Cloud/any VM (Ubuntu/Debian)
─────────────────────────                    ────────────────────────────
MainActivity ──VPN permission──▶ VpnService ──WireGuard (UDP 51820)──▶ wg0
      │                              │ (official GoBackend)            │ NAT
      │ EncryptedSharedPrefs         │ PersistentKeepalive=25         ▼
      │ (config + private key)       │                           internet
      └─ QR / file / paste import ◀──┴── ./vpn qr phone (qrencode)
```

## Components

| Piece | Tech | Notes |
|---|---|---|
| Android UI | Kotlin, Material3 DayNight | `MainActivity`, ViewBinding |
| Tunnel | `com.wireguard.android:tunnel:1.0.20260102` (GoBackend) | Official userspace WireGuard; no custom crypto. TUN owned by backend's internal VpnService; `TunnelService` drives state |
| Config store | EncryptedSharedPreferences (AES256-GCM/SIV) | Excluded from backup |
| State | `ConnectionHub` broadcasts | `CONNECTED` only after a real handshake (`latestHandshake > 0`), never on tunnel-start |
| Reconnect | NetworkCallback + exponential backoff (1s→60s cap) | No tight loops |
| Kill-switch | OS "Block connections without VPN" | App links to system settings |
| Server | `wg-quick@wg0` + UFW + iptables MASQUERADE | One UDP port exposed |
| Client mgmt | `server/vpn` dispatcher + per-client `.conf` (0600) | IP allocation ledger |
| Health | `healthcheck.sh` + systemd timer | Quiet on success |

## Networking

- Full-tunnel default: `AllowedIPs = 0.0.0.0/0`. Server pushes DNS
  (`DNS_SERVER`, default the VPN gateway `10.8.0.1`).
- Split-tunnel: `./vpn add-client NAME --split` → `AllowedIPs = 10.8.0.0/24`.
- IPv6: server is IPv4-only by default. Clients in full-tunnel mode route
  `0.0.0.0/0`; to prevent v6 bypass, either disable IPv6 on the client link
  or set `WIREGUARD_NETWORK_V6` and add `::/0` to AllowedIPs (see
  [server-setup](server-setup.md)). The app never routes around the tunnel.

## What is intentionally NOT here

## What is intentionally NOT here

No open web/API management layer is shipped: enrollment exists only as an
owner-armed, time-boxed, SPKI-pinned endpoint that runs solely inside the
window (see [enrollment](enrollment.md)) — never a public registrar. All
other management is SSH + local scripts. If broader multi-user management
is ever needed, add it behind mutual-TLS, not a password form.
