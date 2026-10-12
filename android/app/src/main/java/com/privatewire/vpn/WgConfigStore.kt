package com.privatewire.vpn

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

/** Encrypted on-device storage for the WireGuard config (contains private key).
 *  Uses the stable security-crypto 1.0.0 API. Excluded from backup (see backup_rules.xml). */
class WgConfigStore(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        PREFS,
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context.applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun saveConfig(conf: String) { prefs.edit().putString(KEY_CONF, conf).apply() }
    fun loadConfig(): String? = prefs.getString(KEY_CONF, null)
    fun clear() { prefs.edit().remove(KEY_CONF).apply() }
    fun hasConfig(): Boolean = !prefs.getString(KEY_CONF, null).isNullOrBlank()

    /** Device identity (private key included) — encrypted, never logged. */
    fun saveIdentity(id: DeviceIdentity) {
        prefs.edit().putString(KEY_PRIV, id.privateKeyB64)
            .putString(KEY_PUB, id.publicKeyB64)
            .putString(KEY_ADDR, id.address)
            .apply()
    }

    fun loadIdentity(): DeviceIdentity? {
        val priv = prefs.getString(KEY_PRIV, null)
        val pub = prefs.getString(KEY_PUB, null)
        val addr = prefs.getString(KEY_ADDR, null)
        return if (priv.isNullOrBlank() || pub.isNullOrBlank() || addr.isNullOrBlank()) null
        else DeviceIdentity(priv, pub, addr)
    }

    fun clearIdentity() {
        prefs.edit().remove(KEY_PRIV).remove(KEY_PUB).remove(KEY_ADDR)
            .remove(KEY_PSK).remove(KEY_ENROLLED).apply()
    }
    fun hasIdentity(): Boolean = loadIdentity() != null

    /** Preshared key issued by the enrollment server (encrypted, never logged). */
    fun saveEnrollPsk(psk: String) { prefs.edit().putString(KEY_PSK, psk).apply() }
    fun loadEnrollPsk(): String? = prefs.getString(KEY_PSK, null)

    /** True once the server has granted this identity an address. */
    fun setEnrolled() { prefs.edit().putBoolean(KEY_ENROLLED, true).apply() }
    fun isEnrolled(): Boolean = prefs.getBoolean(KEY_ENROLLED, false)

    companion object {
        const val PREFS = "privatewire_secure_prefs"
        private const val KEY_CONF = "wg_conf"
        private const val KEY_PRIV = "id_priv"
        private const val KEY_PUB = "id_pub"
        private const val KEY_ADDR = "id_addr"
        private const val KEY_PSK = "enroll_psk"
        private const val KEY_ENROLLED = "enrolled"
    }
}
