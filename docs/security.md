# Security

## Guarantees this project makes

- WireGuard only (official server code + official Android `tunnel`
  library). No custom protocol, no custom crypto, no TLS validation
  to disable (management is over your own SSH, no app backend).
- Keys: `wg genkey`/`genpsk` (CSPRNG) on the owning machine. Server keys
  `0600 root`; client `.conf` files `0600`; never logged, never committed
  (`.gitignore` covers `*.key`, `*.conf`, `.env`, keystores).
- Server exposes **one UDP port**. UFW default-deny incoming; SSH rules are
  never widened by our scripts (they only *add* the WireGuard allow rule).
- `SaveConfig = false`; peer changes go through `wg set`/`syncconf`.
- Logs/diagnostics print peer public-key *prefixes* and handshake ages only.
- App: private key in EncryptedSharedPreferences, `allowBackup=false` +
  data-extraction rules exclude the secure prefs, no analytics, no traffic
  logging.

## Enrollment endpoint (owner-armed only)

- The HTTPS enrollment listener runs solely inside an owner-armed window
  (default ≤15 min) and exits when it lapses; outside the window there is no
  registrar to attack. The code in the `pw-enroll://` URI authorizes peer
  registration while open — share it narrowly and always `enroll-disarm`.
- Server identity is the self-signed cert's SPKI pin, verified byte-for-byte
  by the app; grants pointing at a different server key/endpoint/DNS are
  rejected. The server never sees a device private key.
- Per-IP rate caps (20/min) and a per-window device budget (25) bound
  guessing and flooding; PSKs are never logged.

## Limitations (read before trusting this with anything serious)

1. **Single audit-free codebase.** Written carefully, but not audited.
   Threat model is mass surveillance / untrusted Wi-Fi, not targeted attack.
2. **No pre-shared server identity check in the app UI.** The server public
   key arrives inside the config you import over SSH/QR — if that channel
   is compromised, so is the tunnel. Verify the server fingerprint
   (`./vpn status` never prints secrets; compare via SSH) on first import.
3. **Kill-switch = OS feature.** The app links you to "Block connections
   without VPN"; brief leaks can still occur at boot before Always-on
   starts, and on some OEM ROMs Always-on is unreliable.
4. **IPv4-only default.** Until you configure v6 (see server-setup), IPv6
   traffic on the client bypasses the tunnel. Disable IPv6 on the client
   network or enable the v6 overlay.
5. **DNS.** Full-tunnel + server DNS avoids most leaks, but Android may
   fall back to other resolvers on captive portals; test at
   `dnsleaktest.com` after connecting.
6. **Server sees metadata.** The VPS provider (and anyone with root) can
   observe connection times, volumes, and destination IPs. This hides
   traffic from local networks/ISPs, not from the hosting provider.
7. **PresharedKey is per-client** (extra quantum-resistance layer), but
   rotation requires re-issuing the client config.

## Reporting issues

Do not post configs/keys in issues. Redact `PrivateKey`, `PresharedKey`,
and `Endpoint` (or at least the IP) from anything you share.
