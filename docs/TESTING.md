# TESTING matrix

Honest status of every verification item. Nothing is marked pass unless it
was actually observed.

## Machine-verified here (Windows, git-bash + Node) — 2026-09-21

- [x] `bash -n` syntax check on all 13 server scripts — all pass
      (`server/tests/run-syntax.sh`)
- [x] IP-allocation / duplicate-prevention / naming logic —
      `server/tests/test-alloc.sh`, 13/13 pass (no root, no WireGuard needed)
- [x] All 7 Android XML files well-formed (parsed)
- [x] Unit-test vectors match WireGuard key format (44-char base64, 32 bytes)
- [x] WireGuard `tunnel` API calls verified against upstream sources
      (`Backend`, `Tunnel`, `GoBackend`, `Config`, `Peer`, `Statistics`;
      pinned `1.0.20260102`, confirmed on Maven Central)
- [ ] WgConfigValidator unit tests — `./gradlew :app:testDebugUnitTest`
      (requires JDK + Android SDK; not available in this environment)

## Requires Linux server (not performed here)

- [ ] `deploy-server.sh` end-to-end on Ubuntu 22.04/24.04 + Debian 12
- [ ] `status.sh --self-check` green (forwarding, NAT, egress)
- [ ] Multi-client add/remove, duplicate-IP refusal, revocation handshake-stop
- [ ] `healthcheck.sh` + systemd timer behavior

## Requires physical Android device (not performed here)

- [ ] VPN permission flow, Connect creates tunnel, Disconnect removes it
- [ ] UI shows Connected only after handshake (backend STATE_UP)
- [ ] Network-change reconnect, DNS, full-tunnel routing, leak tests

See repo root test run notes in the final delivery message for what actually
passed in this environment.
