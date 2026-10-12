package com.privatewire.vpn

import com.wireguard.crypto.KeyPair

/** Long-lived identity of this device. The private key never leaves the
 *  device: it is generated here with the official WireGuard library and kept
 *  only in encrypted storage (see WgConfigStore). */
data class DeviceIdentity(
    val privateKeyB64: String,
    val publicKeyB64: String,
    /** Client tunnel address without prefix length, e.g. "10.66.66.7". */
    val address: String,
)

object DeviceIdentityManager {

    /**
     * Load the stored identity or create it (keygen + provisioning record).
     * Thread-safe; runs off the main thread. Never regenerates an existing
     * identity — reinstalls/reset go through explicit flows so a provisioned
     * peer is never silently replaced.
     */
    @Synchronized
    fun ensure(store: WgConfigStore): DeviceIdentity {
        store.loadIdentity()?.let { return it }
        val kp = KeyPair() // official WireGuard lib, Curve25519, on-device
        val pub = kp.publicKey.toBase64()
        val record = LocalDeterministicProvisioning.provision(pub)
        return DeviceIdentity(kp.privateKey.toBase64(), pub, record.clientAddress)
            .also { store.saveIdentity(it) }
    }

    /**
     * Deterministic candidate client address for a public key, in
     * 10.66.66.3–10.66.66.254. Never issues .0 (network), .1 (server) or
     * .2 (legacy official-app profile).
     *
     * This is address ALLOCATION, not cryptography: a plain SHA-256 mapping.
     * Availability is verified by the provisioner against the live server
     * before the peer is registered (see Provisioning).
     */
    fun deriveAddress(publicKeyB64: String): String {
        val raw = java.util.Base64.getDecoder().decode(publicKeyB64.trim())
        require(raw.size == 32) { "not a 32-byte WireGuard key" }
        val h = java.security.MessageDigest.getInstance("SHA-256").digest(raw)
        val v = ((h[0].toInt() and 0xFF) shl 8) or (h[1].toInt() and 0xFF)
        return "10.66.66." + (3 + (v % 252))
    }
}
