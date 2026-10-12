package com.privatewire.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Optional auto-connect after reboot (only if the user enabled it + a config exists). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val settings = AppSettings(context)
        val store = WgConfigStore(context)
        if (settings.autoConnectOnBoot && (store.hasIdentity() || store.hasConfig())) {
            ConnectionHub.userStopped = false
            context.startForegroundService(TunnelService.connectIntent(context))
        }
    }
}
