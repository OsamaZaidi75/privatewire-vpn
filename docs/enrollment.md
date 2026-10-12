# Multi-user enrollment

Additional household/family devices can self-enroll while the owner holds a
short-lived window open. There is **no open registrar**: outside the window
nothing listens at all, and inside it every grant is pinned, validated, and
rate-capped.

## Owner flow (on the server, root shell)

```sh
./vpn enroll-arm 15        # open a 15-minute window (1–120 allowed)
./vpn enroll-status        # window state + cert pin (no secrets)
./vpn enroll-disarm        # close early — always run this when done
```

`enroll-arm` prints an **enrollment code** (and a QR code when `qrencode`
is installed):

```text
pw-enroll://129.80.41.146:8443#<base64-SPKI-pin>
```

Share it with the device owner only, through a channel you trust. It
authorizes peer registration while the window is open. The window also
self-closes: the listener exits when the expiry passes.

Requirements on first arm: `openssl`, `python3`, TCP port **8443**
reachable. The port is opened/closed automatically (UFW when present,
otherwise a temporary tagged iptables rule); if your provider has an extra
firewall (e.g. an OCI security list), add a temporary TCP 8443 ingress rule
yourself and remove it afterwards.

## Device flow (in the app)

Advanced screen (tap the version footer 5×) → **Enroll device** → paste or
type the enrollment code, pick a device name (`a-z 0-9 - _`, max 32 chars)
→ **Enroll**. The app:

1. uses its existing on-device keypair (generated with the official
   WireGuard library — the private key never leaves the phone),
2. POSTs only `{name, pubkey}` over HTTPS pinned to the code's SPKI pin,
3. replaces its tunnel address with the server-assigned one, stores the
   issued preshared key (encrypted), and is ready to **Connect**.

Retry is safe: re-enrolling the same key returns the same address/PSK
instead of burning a second IP. A name already taken by another key, or a
key already enrolled under another name, is rejected (`409`).

## What the server does per enrollment

- Verifies the window file (`/etc/wireguard/.enroll-window`) — else `403`.
- Validates name/pubkey shape; caps request size (4 KiB) — else `400`.
- Assigns the lowest free address in `.3–.254` (`.1` server, `.2` legacy
  reserved; gaps reused) — else `503` when full.
- Generates a fresh per-device preshared key, appends the peer block to
  `wg0.conf`, records `clients/NAME.enrolled` (0600) + the `.ip-alloc`
  ledger, and live-applies (`wg syncconf`, fallback service reload).
- Caps each source IP to 20 requests/minute and each window to 25 new
  devices by default (`429` beyond that).

Revocation is unchanged: `./vpn remove-client NAME` works for enrolled
devices too. `./vpn show-config`/`qr` refuse enrolled records — their
private key lives on the device, so there is nothing to print server-side.

## Security notes

- The enrollment TLS certificate is self-signed and created on first arm
  (RSA-2048, 825 days). The app authenticates it by **SPKI pin only**; a
  grant whose server key/endpoint/DNS/routing differs from the baked-in
  service parameters is rejected even over a pinned connection.
- Logs print names, IPs, and key *prefixes* only — never PSKs.
- Treat the enrollment code like a short-lived password: anyone holding it
  during the window can register a peer. Keep windows short (≤15 min),
  budgets low, and always `./vpn enroll-disarm` when done.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| App: "window is closed" | Window lapsed — owner re-arms and shares a fresh code |
| App: "refused (name_taken)" | Another key owns that name — pick a different device name |
| App: network timeout to `:8443` | Cloud firewall still blocking TCP 8443, or listener disarmed |
| `enroll-arm`: service won't start | `journalctl -u privatewire-enroll` — usually a missing `wg0.conf` or env |
