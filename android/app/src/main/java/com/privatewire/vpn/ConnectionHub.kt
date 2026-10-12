package com.privatewire.vpn

import android.content.Context
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager

/** Process-wide connection-state hub. MainActivity observes broadcasts. */
object ConnectionHub {
    const val ACTION_STATE = "com.privatewire.vpn.STATE"
    const val EXTRA_STATE = "state"
    const val EXTRA_ERROR = "error"
    const val EXTRA_ENDPOINT = "endpoint"
    const val EXTRA_IP = "ip"
    const val EXTRA_SINCE = "since"
    const val EXTRA_RX = "rx"
    const val EXTRA_TX = "tx"

    @Volatile var info: ConnectionInfo = ConnectionInfo()
        private set

    /** Set when the user (or OS revoke) explicitly stops; suppresses auto-reconnect. */
    @Volatile var userStopped = true

    fun post(ctx: Context, info: ConnectionInfo) {
        this.info = info
        val i = Intent(ACTION_STATE)
            .putExtra(EXTRA_STATE, info.state.name)
            .putExtra(EXTRA_ERROR, info.error)
            .putExtra(EXTRA_ENDPOINT, info.serverEndpoint)
            .putExtra(EXTRA_IP, info.assignedIp)
            .putExtra(EXTRA_SINCE, info.connectedSinceMs)
            .putExtra(EXTRA_RX, info.rxBytes)
            .putExtra(EXTRA_TX, info.txBytes)
        LocalBroadcastManager.getInstance(ctx.applicationContext).sendBroadcast(i)
    }

    fun fromIntent(intent: Intent): ConnectionInfo = ConnectionInfo(
        state = runCatching { ConnectionState.valueOf(intent.getStringExtra(EXTRA_STATE) ?: "DISCONNECTED") }
            .getOrDefault(ConnectionState.DISCONNECTED),
        error = intent.getStringExtra(EXTRA_ERROR),
        serverEndpoint = intent.getStringExtra(EXTRA_ENDPOINT).orEmpty(),
        assignedIp = intent.getStringExtra(EXTRA_IP).orEmpty(),
        connectedSinceMs = intent.getLongExtra(EXTRA_SINCE, 0L),
        rxBytes = intent.getLongExtra(EXTRA_RX, 0L),
        txBytes = intent.getLongExtra(EXTRA_TX, 0L),
    )
}
