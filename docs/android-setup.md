# Android setup & build

## Requirements

- JDK 17, Android SDK (Platform 34, Build-Tools 34), ~8 GB free.
- First build needs network (Gradle distribution + Maven Central deps).

## Build

```sh
cd android
# If gradle/wrapper/gradle-wrapper.jar is missing (not vendored), generate it once:
gradle wrapper --gradle-version 8.7
./gradlew :app:assembleDebug          # APK: app/build/outputs/apk/debug/PrivateWire-debug.apk
./gradlew :app:testDebugUnitTest      # unit tests (WgConfigValidatorTest)
./gradlew :app:assembleRelease        # needs a signing key (below)
```

## Install (debug)

```sh
adb install -r app/build/outputs/apk/debug/PrivateWire-debug.apk
```

or copy the APK to the phone and open it (allow "install unknown apps").

## Release signing (your own key — never in the repo)

```sh
keytool -genkeypair -alias privatewire -keyalg RSA -keysize 4096 \
  -validity 9125 -keystore ~/privatewire-release.jks
```

then `~/.gradle/gradle.properties` (NOT in repo):

```properties
PW_STORE_FILE=/home/you/privatewire-release.jks
PW_STORE_PASSWORD=…
PW_KEY_ALIAS=privatewire
PW_KEY_PASSWORD=…
```

and sign via Android Studio or `apksigner`. Debug builds use the
auto-generated `~/.android/debug.keystore` — fine for local testing only.

## Connect (zero-config � no import)

1. Provision the device (owner step, one time per install � see above).
2. In the app tap **Connect** `./vpn qr phone` (or `./vpn show-config phone` → save as `.conf`).
2. In the app: **Scan QR code** / **Import .conf file** / **Paste config**.
3. Tap **Connect** → accept the Android VPN permission dialog
   (`VpnService.prepare` flow) → status shows **Connected** only after the
   WireGuard handshake completes.
4. Legacy manual import lives only in the Advanced dialog (never required).

5. Optional kill-switch: system Settings → VPN → PrivateWire gear →
   enable **Always-on VPN** + **Block connections without VPN**.

## Notes

- Min SDK 26 (WireGuard Go backend requirement path), target/compile 34.
- Configs live in EncryptedSharedPreferences, excluded from backup.
- Camera permission is requested only when scanning QR codes.

## Zero-config flow (current)

No import needed for normal use:

1. Install, open PrivateWire. First launch generates the device WireGuard
   keypair on-device (official `com.wireguard.crypto.KeyPair`) and stores it
   in EncryptedSharedPreferences. The private key never leaves the phone.
2. The VPN owner provisions the device's **public** key on the server
   (Advanced screen shows it, or `adb shell logcat -d -t 4000 | findstr
   "I PrivateWire:"`), verifying the derived address is free with
   `wg show`, then appends the peer to `/etc/wireguard/wg0.conf` and
   live-applies (`wg-quick strip` + `wg syncconf`, fallback
   `systemctl reload wg-quick@wg0`). Never overwrite another peer/IP.
3. Tap **Connect**, accept the VPN permission → Connected (handshake-gated).

Service parameters are non-secret constants (`ServiceConfig.kt`):
endpoint `129.80.41.146:51820`, server public key, DNS `10.66.66.1`,
`0.0.0.0/0`, keepalive 25. Client address is derived deterministically
(`10.66.66.3–254`, never `.0/.1/.2`); server-side assignment via a future
authenticated HTTPS API can replace `LocalDeterministicProvisioning`
without touching UI/tunnel code.

Manual import (QR/file/paste) exists only in the hidden Advanced dialog
(tap the version footer 5×), plus identity reset and VPN settings shortcut.

## Verified zero-config build (2026-09-22, OnePlus 9R, live device)

Built offline-clean with JDK 17 + Gradle 8.7 + SDK 34:

- APK: `android/app/build/outputs/apk/debug/PrivateWire-debug.apk` (~21 MB,
  debug-signed, installs over the official client side-by-side)
- Debug applicationId is `com.privatewire.vpn.debug`
  (`applicationIdSuffix = ".debug"`); release stays `com.privatewire.vpn`
- APK contains the official WireGuard natives for all ABIs
  (`lib/arm64-v8a/libwg-go.so`, `libwg.so`, `libwg-quick.so`, …)
- Unit tests: 18/18 pass (`WgConfigValidatorTest` 9,
  `DeviceIdentityTest` 5, `ServiceConfigTest` 4)
- Security: no private keys in source; private key generated on-device,
  stored only in EncryptedSharedPreferences (AES256-GCM, excluded from
  backup); logcat clean (no crashes, no key material)

Device test results (peer `10.66.66.98`, server `129.80.41.146:51820`):
launch ok, keygen ok, provisioned without touching the existing `.2` peer,
real handshake + growing rx/tx, `tun0` up, public IP = server IP, VPN DNS
`10.66.66.1`, `::/0 unreachable` (no IPv6 bypass), disconnect restores
direct internet, reconnect works, force-stop/reopen keeps identity.

## On-device verification checklist (needs the phone + ADB)

Server `129.80.41.146:51820`, client address `10.66.66.2/32`.
Do NOT change anything server-side for this.

```sh
adb install -r android/app/build/outputs/apk/debug/PrivateWire-debug.apk
```

1. Open PrivateWire → import the existing working config (QR / `.conf` /
   paste — same `10.66.66.2` tunnel config the official app uses).
2. Tap **Connect**, accept the VPN permission dialog.
3. Status must show **Connected** only after a real WireGuard handshake
   (the app gates CONNECTED on handshake, never fakes it).
4. Check: `curl ifconfig.me` (or browser) → `129.80.41.146`; DNS resolves;
   `adb shell ping -c2 10.66.66.1` works through the tunnel.
5. IPv6 leak check: with mobile data IPv6 available, confirm no route
   bypasses the tunnel (app sets no IPv6 tunnel routes, matching server).
6. Disconnect → normal internet returns; reconnect works; restart the app
   with no config loss; `./vpn status` on the server shows the handshake.
