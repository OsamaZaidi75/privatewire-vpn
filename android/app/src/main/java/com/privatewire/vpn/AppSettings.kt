package com.privatewire.vpn

import android.content.Context

/** Plain (non-secret) user settings. */
class AppSettings(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences("privatewire_settings", Context.MODE_PRIVATE)

    var autoReconnect: Boolean
        get() = prefs.getBoolean("auto_reconnect", true)
        set(v) { prefs.edit().putBoolean("auto_reconnect", v).apply() }

    /** Reminder flag only: actual kill-switch is the OS "Block connections without VPN" setting. */
    var killSwitch: Boolean
        get() = prefs.getBoolean("kill_switch", false)
        set(v) { prefs.edit().putBoolean("kill_switch", v).apply() }

    /** On by default: zero-touch means the tunnel comes back after reboot. */
    var autoConnectOnBoot: Boolean
        get() = prefs.getBoolean("auto_boot", true)
        set(v) { prefs.edit().putBoolean("auto_boot", v).apply() }
}
