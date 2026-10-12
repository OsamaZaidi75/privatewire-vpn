package com.privatewire.vpn

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/**
 * Foreground service that owns the WireGuard backend.
 *
 * The TUN itself is managed by the OFFICIAL WireGuard backend's internal
 * VpnService (GoBackend$VpnService, merged from the tunnel AAR) — this
 * service only drives state, verifies handshakes, polls stats, and handles
 * reconnects. No custom crypto, no custom protocol.
 *
 * CONNECTED is broadcast only after a real WireGuard handshake is observed
 * (peer latestHandshake > 0), never on "tunnel starting".
 */
class TunnelService : Service() {

    private lateinit var store: WgConfigStore
    private lateinit var settings: AppSettings
    private val main = Handler(Looper.getMainLooper())
    private val stopped = AtomicBoolean(false)

    private var reconnectAttempt = 0
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        stopped.set(false)
        store = WgConfigStore(this)
        settings = AppSettings(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val inline = intent.getStringExtra(EXTRA_CONFIG) ?: resolveConfig()
                connectInternal(inline)
            }
            ACTION_DISCONNECT -> disconnectInternal(userInitiated = true)
            ACTION_STATS -> pushStats()
        }
        return START_STICKY
    }

    /**
     * Register this identity with the provisioning service and persist the
     * grant (server-assigned address + preshared key, both encrypted).
     * Returns false after broadcasting the error — tapping Connect retries.
     */
    private fun ensureProvisioned(id: DeviceIdentity): Boolean {
        val outcome = EnrollmentClient.autoEnroll(
            id.publicKeyB64, EnrollmentClient.defaultTarget(),
        )
        if (outcome is EnrollOutcome.Granted) {
            store.saveIdentity(id.copy(address = outcome.grant.address))
            store.saveEnrollPsk(outcome.grant.psk)
            store.setEnrolled()
            return true
        }
        val detail = when (outcome) {
            is EnrollOutcome.Granted -> ""
            EnrollOutcome.WindowClosed -> "registration closed"
            is EnrollOutcome.Conflict -> "name clash"
            is EnrollOutcome.RateLimited -> "too many attempts"
            EnrollOutcome.ServerFull -> "server full"
            is EnrollOutcome.InvalidRequest -> "bad request"
            is EnrollOutcome.InvalidGrant -> "unverified reply"
            is EnrollOutcome.ServerError -> "server error ${outcome.code}"
            is EnrollOutcome.Network -> outcome.detail
        }
        broadcast(ConnectionInfo(ConnectionState.ERROR, getString(R.string.enroll_failed, detail)))
        return false
    }

    // ---------- connect / disconnect ----------

    /**
     * Normal path: assemble the live config from the device identity
     * (zero-config — no import needed). Falls back to a legacy manually
     * imported config when present (hidden Advanced feature).
     */
    private fun resolveConfig(): String? {
        val id = runCatching { DeviceIdentityManager.ensure(store) }.getOrNull()
        if (id != null) return ServiceConfig.buildConfig(id, store.loadEnrollPsk())
        return store.loadConfig()
    }

    private fun connectInternal(confText: String?) {
        if (confText.isNullOrBlank()) {
            broadcast(ConnectionInfo(ConnectionState.ERROR, getString(R.string.err_no_config)))
            stopSelf()
            return
        }
        when (val parsed = WgConfigValidator.validate(confText)) {
            is WgConfigValidator.Result.Err -> {
                broadcast(ConnectionInfo(ConnectionState.ERROR, parsed.reason))
                stopSelf()
                return
            }
            WgConfigValidator.Result.Ok -> Unit
        }
        // Foreground first: the backend starts its VpnService, which the
        // system forbids while the app is in the background.
        startForeground(NOTIF_ID, buildNotif(getString(R.string.state_connecting)))
        broadcast(ConnectionInfo(ConnectionState.CONNECTING))
        registerNetCallback()

        Thread {
            try {
                // Zero-touch gate: an identity with no grant yet registers
                // itself before the backend starts (same key always yields
                // the same grant). Legacy manual configs bypass this.
                var live = confText
                val ident = runCatching { DeviceIdentityManager.ensure(store) }.getOrNull()
                if (ident != null && store.loadConfig().isNullOrBlank()) {
                    if (!store.isEnrolled() && !ensureProvisioned(ident)) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        return@Thread
                    }
                    live = ServiceConfig.buildConfig(
                        store.loadIdentity() ?: ident, store.loadEnrollPsk(),
                    )
                }
                val config = Config.parse(
                    BufferedReader(InputStreamReader(ByteArrayInputStream(live.toByteArray()))),
                )
                tunnel.lastConfig = config
                ConnectionHub.userStopped = false
                stopped.set(false)
                backend(this).setState(tunnel, Tunnel.State.UP, config)
                // UP/DOWN callbacks arrive via tunnel.onStateChange.
                awaitFirstHandshake()
            } catch (e: Exception) {
                // Pin the error: suppress any late DOWN callback from clobbering it.
                ConnectionHub.userStopped = true
                stopped.set(true)
                unregisterNetCallback()
                broadcast(ConnectionInfo(ConnectionState.ERROR, friendlyError(e)))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }.start()
    }

    /**
     * Gate CONNECTED on a real handshake. GoBackend reports UP once the TUN
     * exists; without this wait the UI could claim "Connected" to a dead peer.
     */
    private fun awaitFirstHandshake() {
        val deadline = SystemClock.elapsedRealtime() + HANDSHAKE_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline && !stopped.get()) {
            if (handshakeObserved()) {
                val (ep, addr) = WgConfigValidator.summarize(store.loadConfig() ?: "")
                val (rx, tx) = currentTotals()
                broadcast(
                    ConnectionInfo(
                        state = ConnectionState.CONNECTED,
                        serverEndpoint = ep,
                        assignedIp = addr,
                        connectedSinceMs = System.currentTimeMillis(),
                        rxBytes = rx,
                        txBytes = tx,
                    ),
                )
                main.post { startForeground(NOTIF_ID, buildNotif(getString(R.string.state_connected))) }
                return
            }
            // If the backend already went DOWN (bad key, etc.), stop waiting.
            if (ConnectionHub.info.state == ConnectionState.DISCONNECTED) return
            SystemClock.sleep(1000)
        }
        if (stopped.get() || ConnectionHub.info.state == ConnectionState.CONNECTED) return
        // Tear down quietly, then leave ERROR as the final visible state.
        ConnectionHub.userStopped = true // no auto-reconnect after an explicit failure
        disconnectInternal(userInitiated = false, keepFinalState = true)
        broadcast(ConnectionInfo(ConnectionState.ERROR, getString(R.string.err_tunnel_timeout)))
    }

    private fun handshakeObserved(): Boolean {
        val cfg = tunnel.lastConfig ?: return false
        val key = cfg.peers.firstOrNull()?.publicKey ?: return false
        val be = peekBackend() ?: return false
        return runCatching {
            val peer = be.getStatistics(tunnel).peer(key)
            (peer?.latestHandshakeEpochMillis() ?: 0L) > 0L
        }.getOrDefault(false)
    }

    private fun currentTotals(): Pair<Long, Long> {
        val be = peekBackend() ?: return 0L to 0L
        return runCatching {
            val s = be.getStatistics(tunnel)
            s.totalRx() to s.totalTx()
        }.getOrDefault(0L to 0L)
    }

    private fun pushStats() {
        val cur = ConnectionHub.info
        if (cur.state != ConnectionState.CONNECTED) return
        val (rx, tx) = currentTotals()
        broadcast(cur.copy(rxBytes = rx, txBytes = tx))
    }

    private fun disconnectInternal(userInitiated: Boolean, keepFinalState: Boolean = false) {
        if (userInitiated) ConnectionHub.userStopped = true
        stopped.set(true)
        unregisterNetCallback()
        reconnectAttempt = 0
        if (!keepFinalState) broadcast(ConnectionInfo(ConnectionState.DISCONNECTING))
        Thread {
            try {
                // Config may be null for DOWN per Backend contract.
                peekBackend()?.setState(tunnel, Tunnel.State.DOWN, tunnel.lastConfig)
            } catch (_: Exception) { /* best effort */ } finally {
                tunnel.lastConfig = null
                if (!keepFinalState) broadcast(ConnectionInfo(ConnectionState.DISCONNECTED))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }.start()
    }

    // ---------- Tunnel ----------

    private val tunnel = object : Tunnel {
        @Volatile var lastConfig: Config? = null
        override fun getName(): String = TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            when (newState) {
                Tunnel.State.UP -> {
                    reconnectAttempt = 0
                    // Handshake gate runs in awaitFirstHandshake(); nothing to do here.
                }
                Tunnel.State.DOWN -> {
                    val wasLive = ConnectionHub.info.state == ConnectionState.CONNECTED ||
                        ConnectionHub.info.state == ConnectionState.CONNECTING
                    if (!ConnectionHub.userStopped && settings.autoReconnect && wasLive) {
                        scheduleReconnect()
                    } else if (!stopped.get()) {
                        broadcast(ConnectionInfo(ConnectionState.DISCONNECTED))
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
                else -> Unit
            }
        }
    }

    // ---------- auto-reconnect with exponential backoff ----------

    private fun scheduleReconnect() {
        val delayMs = min(60_000L, 1_000L shl min(reconnectAttempt, 6)) // 1s..60s cap, no tight loop
        reconnectAttempt++
        stopped.set(false)
        broadcast(ConnectionInfo(ConnectionState.CONNECTING, getString(R.string.state_reconnecting)))
        main.postDelayed({
            if (!ConnectionHub.userStopped && settings.autoReconnect && !stopped.get()) {
                resolveConfig()?.let { connectInternal(it) }
            }
        }, delayMs)
    }

    private fun registerNetCallback() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                // WireGuard roams on its own; only nudge when we had a live
                // tunnel, and through the same backoff path.
                if (ConnectionHub.info.state == ConnectionState.CONNECTED && settings.autoReconnect) {
                    scheduleReconnect()
                }
            }
        }
        netCallback = cb
        runCatching {
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                cb,
            )
        }
    }

    private fun unregisterNetCallback() {
        netCallback?.let {
            runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it) }
        }
        netCallback = null
    }

    // ---------- helpers ----------

    private fun friendlyError(e: Exception): String {
        val msg = e.message.orEmpty()
        return when {
            msg.contains("VPN_NOT_AUTHORIZED", ignoreCase = true) -> getString(R.string.err_vpn_denied)
            msg.contains("DNS", ignoreCase = true) -> getString(R.string.err_dns, msg)
            else -> msg.ifBlank { getString(R.string.err_backend) }
        }
    }

    private fun broadcast(info: ConnectionInfo) = ConnectionHub.post(this, info)

    private fun buildNotif(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopped.set(true)
        unregisterNetCallback()
        super.onDestroy()
    }

    companion object {
        const val TUNNEL_NAME = "privatewire" // <=15 chars, matches backend NAME_PATTERN
        const val CHANNEL_ID = "privatewire_tunnel"
        const val NOTIF_ID = 1001
        const val ACTION_CONNECT = "com.privatewire.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.privatewire.vpn.DISCONNECT"
        const val ACTION_STATS = "com.privatewire.vpn.STATS"
        const val EXTRA_CONFIG = "extra_config"
        private const val HANDSHAKE_TIMEOUT_MS = 30_000L

        @Volatile private var backendRef: Backend? = null

        /** Single backend for the process (GoBackend holds static tunnel state). */
        fun backend(ctx: Context): Backend = synchronized(this) {
            backendRef ?: GoBackend(ctx.applicationContext).also { backendRef = it }
        }

        /** Existing backend, or null — never creates one (teardown/stats paths). */
        fun peekBackend(): Backend? = synchronized(this) { backendRef }

        fun connectIntent(ctx: Context, inlineConfig: String? = null): Intent =
            Intent(ctx, TunnelService::class.java).apply {
                action = ACTION_CONNECT
                if (inlineConfig != null) putExtra(EXTRA_CONFIG, inlineConfig)
            }

        fun disconnectIntent(ctx: Context): Intent =
            Intent(ctx, TunnelService::class.java).apply { action = ACTION_DISCONNECT }
    }
}
