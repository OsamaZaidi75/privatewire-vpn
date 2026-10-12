package com.privatewire.vpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class PrivateWireApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                TunnelService.CHANNEL_ID,
                getString(R.string.notif_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        // Zero-touch: every install owns a device identity AND registers it
        // in the background, so the first Connect just works. The public key
        // is public (shared with the server, visible in `wg show`); the
        // private key never leaves encrypted storage and is never logged.
        Thread {
            runCatching {
                val store = WgConfigStore(this)
                val id = DeviceIdentityManager.ensure(store)
                android.util.Log.i(TAG, "device ready address=${id.address} publicKey=${id.publicKeyB64}")
                if (!store.isEnrolled() && store.loadConfig().isNullOrBlank()) {
                    when (val r = EnrollmentClient.autoEnroll(
                        id.publicKeyB64, EnrollmentClient.defaultTarget(),
                    )) {
                        is EnrollOutcome.Granted -> {
                            store.saveIdentity(id.copy(address = r.grant.address))
                            store.saveEnrollPsk(r.grant.psk)
                            store.setEnrolled()
                            android.util.Log.i(TAG, "auto-enrolled address=${r.grant.address}")
                        }
                        else -> android.util.Log.w(TAG, "auto-enroll pending: $r")
                    }
                }
            }.onFailure {
                android.util.Log.e(TAG, "identity setup failed", it)
            }
        }.start()
    }

    companion object {
        const val TAG = "PrivateWire"
    }
}
