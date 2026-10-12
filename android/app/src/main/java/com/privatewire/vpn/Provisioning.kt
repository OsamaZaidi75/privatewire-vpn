package com.privatewire.vpn

/**
 * How a device identity becomes a registered server peer.
 *
 * Two server halves exist:
 *  - [EnrollmentClient]: the zero-touch path. On first launch (and on every
 *    Connect while unprovisioned) the device POSTs its public key to the
 *    SPKI-pinned provisioning endpoint and receives a server-assigned
 *    address (+ preshared key), automatically. The device private key is
 *    never involved.
 *  - [LocalDeterministicProvisioning]: dev/offline fallback. Derives the
 *    client address locally; the server half is performed out-of-band by the
 *    VPN owner over SSH (read the device public key from the app's Advanced
 *    screen or logcat, verify the address is free with `wg show`, then append
 *    the peer to wg0.conf and live-apply). The device private key is never
 *    involved.
 *
 * Never add an unauthenticated public registration endpoint — that would let
 * arbitrary internet users register WireGuard peers.
 */
data class ProvisionRecord(val clientAddress: String, val method: String)

interface Provisioning {
    fun provision(publicKeyB64: String): ProvisionRecord
}

object LocalDeterministicProvisioning : Provisioning {
    override fun provision(publicKeyB64: String): ProvisionRecord =
        ProvisionRecord(DeviceIdentityManager.deriveAddress(publicKeyB64), "local-deterministic/dev")
}
