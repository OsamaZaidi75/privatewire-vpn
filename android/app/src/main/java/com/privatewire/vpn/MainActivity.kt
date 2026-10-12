package com.privatewire.vpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.Formatter
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.privatewire.vpn.databinding.ActivityMainBinding

/**
 * Zero-touch UI: status + Connect/Disconnect. The first launch generates the
 * on-device keypair and the tunnel registers itself with the provisioning
 * service before connecting — Install, Open, Connect is the whole flow.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var store: WgConfigStore
    private val ui = Handler(Looper.getMainLooper())
    private var ticking = false

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) startTunnel()
        else showError(getString(R.string.err_vpn_denied))
    }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            render(ConnectionHub.fromIntent(intent))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        store = WgConfigStore(this)

        binding.btnConnect.setOnClickListener { onConnect() }
        binding.btnDisconnect.setOnClickListener { onDisconnect() }
        binding.textLocation.text = ServiceConfig.LOCATION
        binding.textEndpoint.text = ServiceConfig.DISPLAY_ENDPOINT

        LocalBroadcastManager.getInstance(this).registerReceiver(
            stateReceiver, IntentFilter(ConnectionHub.ACTION_STATE),
        )
        // Identity is ensured at app start (background); refresh once ready.
        Thread {
            runCatching { DeviceIdentityManager.ensure(store) }
            runOnUiThread { render(ConnectionHub.info) }
        }.start()
        render(ConnectionHub.info)
        startTicker()
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this).unregisterReceiver(stateReceiver)
        ticking = false
        super.onDestroy()
    }

    // ---------- connect flow (Android VPN permission) ----------

    private fun onConnect() {
        ConnectionHub.userStopped = false
        binding.btnConnect.isEnabled = false
        Thread {
            val ready = runCatching { DeviceIdentityManager.ensure(store) }.isSuccess || store.hasConfig()
            runOnUiThread {
                if (!ready) {
                    showError(getString(R.string.err_no_identity))
                    render(ConnectionHub.info)
                    return@runOnUiThread
                }
                val prep = VpnService.prepare(this)
                if (prep != null) vpnPermission.launch(prep) else startTunnel()
            }
        }.start()
    }

    private fun startTunnel() {
        startForegroundService(TunnelService.connectIntent(this))
    }

    private fun onDisconnect() {
        ConnectionHub.userStopped = true
        startService(TunnelService.disconnectIntent(this))
    }

    // ---------- render (never fake CONNECTED) ----------

    private fun render(info: ConnectionInfo) {
        binding.textStatus.text = when (info.state) {
            ConnectionState.CONNECTED -> getString(R.string.state_connected)
            ConnectionState.CONNECTING -> getString(R.string.state_connecting)
            ConnectionState.DISCONNECTING -> getString(R.string.state_disconnecting)
            ConnectionState.ERROR -> getString(R.string.state_error, info.error ?: "")
            ConnectionState.DISCONNECTED -> getString(R.string.state_disconnected)
        }
        val connected = info.state == ConnectionState.CONNECTED
        val busy = info.state == ConnectionState.CONNECTING || info.state == ConnectionState.DISCONNECTING
        val ready = store.hasIdentity() || store.hasConfig()
        binding.btnConnect.isEnabled = !connected && !busy && ready
        binding.btnDisconnect.isEnabled = connected || busy
        val liveIp = info.assignedIp.ifEmpty { null }
        binding.textAssignedIp.text = when {
            connected && liveIp != null -> liveIp
            else -> store.loadIdentity()?.address ?: liveIp ?: "—"
        }
        binding.textUp.text = Formatter.formatShortFileSize(this, info.txBytes)
        binding.textDown.text = Formatter.formatShortFileSize(this, info.rxBytes)
        binding.errorBox.visibility = if (info.state == ConnectionState.ERROR) View.VISIBLE else View.GONE
        if (info.state == ConnectionState.ERROR) binding.errorText.text = info.error
        binding.textSetupHint.visibility = if (ready) View.GONE else View.VISIBLE
    }

    private fun showError(msg: String) {
        render(ConnectionInfo(ConnectionState.ERROR, msg))
    }

    private fun startTicker() {
        ticking = true
        val r = object : Runnable {
            override fun run() {
                if (!ticking) return
                val info = ConnectionHub.info
                if (info.state == ConnectionState.CONNECTED) {
                    val secs = ((System.currentTimeMillis() - info.connectedSinceMs) / 1000).coerceAtLeast(0)
                    binding.textDuration.text = "%02d:%02d:%02d".format(secs / 3600, (secs % 3600) / 60, secs % 60)
                    // Ask the service to refresh rx/tx from the WireGuard backend.
                    startService(Intent(this@MainActivity, TunnelService::class.java).apply {
                        action = TunnelService.ACTION_STATS
                    })
                } else {
                    binding.textDuration.text = "—"
                }
                ui.postDelayed(this, 1000)
            }
        }
        ui.post(r)
    }
}
