package com.privatewire.vpn

/** Single source of truth for UI state. CONNECTED is set only after an
 *  actual WireGuard handshake is observed (see TunnelService). */
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    ERROR,
}

data class ConnectionInfo(
    val state: ConnectionState = ConnectionState.DISCONNECTED,
    val error: String? = null,
    val serverEndpoint: String = "",
    val assignedIp: String = "",
    val connectedSinceMs: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
)
