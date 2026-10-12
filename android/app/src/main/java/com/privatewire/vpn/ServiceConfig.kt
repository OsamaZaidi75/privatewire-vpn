package com.privatewire.vpn

/**
 * Non-secret service parameters for the PrivateWire personal VPN.
 *
 * Everything here is public by design — the server public key, endpoint,
 * DNS and routing are visible in any WireGuard client configuration and are
 * safe to ship in the app. No private keys or secrets live in this file.
 */
object ServiceConfig {
    const val ENDPOINT_HOST = "129.80.41.146"
    const val ENDPOINT_PORT = 51820
    const val DISPLAY_ENDPOINT = "129.80.41.146:51820"

    /** Server WireGuard public key (read from the live server via `wg show`). */
    const val SERVER_PUBLIC_KEY = "fqh2Oix5SsBGTxEtx3lWNhKcutleb4TQ7LtepRzX8Fo="

    const val CLIENT_DNS = "10.66.66.1"
    const val ALLOWED_IPS = "0.0.0.0/0"
    const val KEEPALIVE = 25

    const val LOCATION = "United States · Ashburn"

    /**
     * Zero-touch provisioning endpoint (friends build, owner-accepted risk:
     * anyone holding the APK may register a peer). The host/port/pin here
     * are non-secret bootstrap: the pin authenticates the server (fail
     * closed on mismatch) but authorizes nothing — registration itself is
     * open. If the server cert is ever regenerated, update the pin or every
     * install fails closed here.
     */
    const val ENROLL_HOST = ENDPOINT_HOST
    const val ENROLL_PORT = 8443
    const val ENROLL_PIN = "GJfxuislhas8K4PwHdg3pidIF5D1uOqwxM50gulc/Mo="

    /**
     * Assemble a complete .conf from a device identity. The private key comes
     * only from encrypted on-device storage — never from resources or code.
     * The optional preshared key is the one issued by the enrollment server
     * (stored encrypted alongside the identity); manual/dev setups omit it.
     */
    fun buildConfig(identity: DeviceIdentity, psk: String? = null): String =
        "[Interface]\n" +
            "PrivateKey = " + identity.privateKeyB64 + "\n" +
            "Address = " + identity.address + "/32\n" +
            "DNS = " + CLIENT_DNS + "\n" +
            "\n" +
            "[Peer]\n" +
            "PublicKey = " + SERVER_PUBLIC_KEY + "\n" +
            (if (psk.isNullOrBlank()) "" else "PresharedKey = " + psk.trim() + "\n") +
            "AllowedIPs = " + ALLOWED_IPS + "\n" +
            "Endpoint = " + DISPLAY_ENDPOINT + "\n" +
            "PersistentKeepalive = " + KEEPALIVE + "\n"
}
