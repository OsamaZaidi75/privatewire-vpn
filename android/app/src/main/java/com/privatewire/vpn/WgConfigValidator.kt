package com.privatewire.vpn

import android.util.Base64

/**
 * Pure-Kotlin pre-validation of WireGuard .conf text before it reaches the
 * official parser/backend. Fast, testable, no Android dependencies.
 */
object WgConfigValidator {

    sealed interface Result {
        data object Ok : Result
        data class Err(val reason: String) : Result
    }

    private val KEY_RE = Regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")
    private val SECTION_RE = Regex("^\\[(Interface|Peer)]$")
    private val KV_RE = Regex("^([A-Za-z]+)\\s*=\\s*(.+?)\\s*$")
    private val CIDR_RE = Regex("^([0-9.]+|[:0-9a-fA-F]+)(/(\\d{1,3}))?$")

    fun validate(text: String): Result {
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        if (lines.isEmpty()) return Result.Err("configuration is empty")
        var section = ""
        var hasInterface = false
        var hasPeer = false
        var hasPrivateKey = false
        var hasAddress = false
        var hasPublicKey = false
        var hasEndpoint = false
        var hasAllowedIps = false

        for (line in lines) {
            val sec = SECTION_RE.matchEntire(line)
            if (sec != null) {
                section = sec.groupValues[1]
                if (section == "Interface") hasInterface = true
                if (section == "Peer") hasPeer = true
                continue
            }
            val kv = KV_RE.matchEntire(line) ?: return Result.Err("cannot parse line: $line")
            val (key, value) = kv.destructured
            when (section) {
                "Interface" -> when (key) {
                    "PrivateKey" -> {
                        if (!KEY_RE.matches(value)) return Result.Err("Interface.PrivateKey is not a valid WireGuard key")
                        hasPrivateKey = true
                    }
                    "Address" -> {
                        value.split(",").forEach {
                            if (!CIDR_RE.matches(it.trim())) return Result.Err("bad Interface.Address: $it")
                        }
                        hasAddress = true
                    }
                    "DNS" -> Unit // free-form IPs/hostnames, backend parses
                    else -> return Result.Err("unsupported Interface key: $key")
                }
                "Peer" -> when (key) {
                    "PublicKey", "PresharedKey" -> {
                        if (!KEY_RE.matches(value)) return Result.Err("Peer.$key is not a valid WireGuard key")
                        if (key == "PublicKey") hasPublicKey = true
                    }
                    "AllowedIPs" -> {
                        value.split(",").forEach {
                            if (!CIDR_RE.matches(it.trim())) return Result.Err("bad Peer.AllowedIPs: $it")
                        }
                        hasAllowedIps = true
                    }
                    "Endpoint" -> {
                        if (!value.contains(":")) return Result.Err("Peer.Endpoint must be host:port")
                        hasEndpoint = true
                    }
                    "PersistentKeepalive" -> {
                        value.toIntOrNull() ?: return Result.Err("bad PersistentKeepalive: $value")
                    }
                    else -> return Result.Err("unsupported Peer key: $key")
                }
                else -> return Result.Err("key/value outside [Interface]/[Peer]: $line")
            }
        }
        if (!hasInterface) return Result.Err("missing [Interface]")
        if (!hasPeer) return Result.Err("missing [Peer]")
        if (!hasPrivateKey) return Result.Err("missing Interface.PrivateKey")
        if (!hasAddress) return Result.Err("missing Interface.Address")
        if (!hasPublicKey) return Result.Err("missing Peer.PublicKey")
        if (!hasEndpoint) return Result.Err("missing Peer.Endpoint")
        if (!hasAllowedIps) return Result.Err("missing Peer.AllowedIPs")
        return Result.Ok
    }

    /** Extract Endpoint + Address for display without exposing secrets. */
    fun summarize(text: String): Pair<String, String> {
        var endpoint = ""
        var address = ""
        var section = ""
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line == "[Interface]") section = "Interface"
            else if (line == "[Peer]") section = "Peer"
            else if (section == "Interface" && line.startsWith("Address")) address = line.substringAfter("=").trim()
            else if (section == "Peer" && line.startsWith("Endpoint")) endpoint = line.substringAfter("=").trim()
        }
        return endpoint to address
    }

    fun isPlausibleKey(s: String): Boolean = runCatching {
        val b = Base64.decode(s, Base64.DEFAULT); b.size == 32 && KEY_RE.matches(s.trim())
    }.getOrDefault(false)
}
