package com.privatewire.vpn

import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Authenticated self-enrollment: the device registers its (on-device
 * generated) public key with the server while the owner holds an
 * enrollment window open, and gets back a server-assigned tunnel address.
 *
 * Trust model: the server uses a self-signed TLS certificate. There is no
 * CA and no hostname trust — the SPKI pin (sha256 of the DER-encoded
 * SubjectPublicKeyInfo, base64) printed by `./vpn enroll-arm` IS the server
 * identity. The connection is rejected unless the leaf certificate's SPKI
 * digest matches the pin byte-for-byte.
 *
 * The device private key is never involved: only the public key is sent.
 * Pure JVM (no android.* imports) so the codec/validation is unit-testable.
 */
object EnrollmentValidator {

    private val NAME_RE = Regex("^[A-Za-z0-9_-]{1,32}$")
    private val KEY_RE = Regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")

    fun isValidName(s: String): Boolean = NAME_RE.matches(s)

    fun isValidKey(s: String): Boolean {
        val t = s.trim()
        if (!KEY_RE.matches(t)) return false
        return runCatching {
            java.util.Base64.getDecoder().decode(t).size == 32
        }.getOrDefault(false)
    }

    /** SPKI pin: base64 of a 32-byte sha256 digest. */
    fun isValidPin(s: String): Boolean = runCatching {
        val b = java.util.Base64.getDecoder().decode(s.trim())
        b.size == 32
    }.getOrDefault(false)
}

/** Enrollment server location + SPKI pin. */
data class EnrollTarget(val host: String, val port: Int, val pinB64: String)

/** Server grant: everything the app needs to build the tunnel config. */
data class EnrollGrant(
    val address: String,
    val serverPubkey: String,
    val endpoint: String,
    val dns: String,
    val psk: String,
    val allowedIps: String,
)

sealed interface EnrollOutcome {
    data class Granted(val grant: EnrollGrant) : EnrollOutcome
    data object WindowClosed : EnrollOutcome
    data class Conflict(val detail: String) : EnrollOutcome
    data class RateLimited(val retryAfterSec: Int?) : EnrollOutcome
    data object ServerFull : EnrollOutcome
    data class InvalidRequest(val detail: String) : EnrollOutcome
    data class InvalidGrant(val detail: String) : EnrollOutcome
    data class ServerError(val code: Int) : EnrollOutcome
    data class Network(val detail: String) : EnrollOutcome
}

object EnrollmentCodec {

    /** Enrollment code the owner shares: pw-enroll://host:port#pin, or a bare pin. */
    fun parseCode(text: String, defaultHost: String, defaultPort: Int): EnrollTarget? {
        val t = text.trim()
        if (t.isEmpty()) return null
        if (!t.contains("://")) {
            if (!EnrollmentValidator.isValidPin(t)) return null
            if (defaultHost.isBlank() || defaultPort !in 1..65535) return null
            return EnrollTarget(defaultHost, defaultPort, t.trim())
        }
        if (!t.startsWith("pw-enroll://")) return null
        val rest = t.removePrefix("pw-enroll://")
        val hash = rest.indexOf('#')
        if (hash < 0) return null
        val pin = rest.substring(hash + 1).trim()
        if (!EnrollmentValidator.isValidPin(pin)) return null
        val authority = rest.substring(0, hash)
        if (authority.isEmpty() || authority.any { it.isWhitespace() }) return null
        val colon = authority.lastIndexOf(':')
        if (colon < 0) return null
        val host = authority.substring(0, colon)
        val port = authority.substring(colon + 1).toIntOrNull() ?: return null
        if (host.isEmpty() || port !in 1..65535) return null
        return EnrollTarget(host, port, pin)
    }

    fun buildRequest(name: String, pubkey: String): String =
        "{\"name\":" + esc(name) + ",\"pubkey\":" + esc(pubkey) + "}"

    private fun esc(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) when (c) {
            '"' -> sb.append("\\\"")
            '\\' -> sb.append("\\\\")
            '\n' -> sb.append("\\n")
            '\r' -> sb.append("\\r")
            '\t' -> sb.append("\\t")
            '\b' -> sb.append("\\b")
            '\u000C' -> sb.append("\\f")
            else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
        }
        return sb.append("\"").toString()
    }

    /**
     * Strict parser for flat {"k":"v",...} objects (string values only).
     * Rejects duplicates, non-string values, trailing garbage. Returns null
     * on any malformed input.
     */
    fun parseFlatObject(json: String): Map<String, String>? {
        var i = 0
        fun ws() { while (i < json.length && json[i].isWhitespace()) i++ }
        fun parseString(): String? {
            if (i >= json.length || json[i] != '"') return null
            i++
            val sb = StringBuilder()
            while (i < json.length) {
                val c = json[i++]
                if (c == '"') return sb.toString()
                if (c != '\\') { sb.append(c); continue }
                if (i >= json.length) return null
                when (json[i++]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    '/' -> sb.append('/')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        if (i + 4 > json.length) return null
                        val cp = json.substring(i, i + 4).toIntOrNull(16) ?: return null
                        sb.append(cp.toChar()); i += 4
                    }
                    else -> return null
                }
            }
            return null
        }
        ws()
        if (i >= json.length || json[i++] != '{') return null
        val out = LinkedHashMap<String, String>()
        ws()
        if (i < json.length && json[i] == '}') {
            i++; ws()
            return if (i == json.length) out else null
        }
        while (true) {
            ws()
            val k = parseString() ?: return null
            ws()
            if (i >= json.length || json[i++] != ':') return null
            ws()
            val v = parseString() ?: return null
            if (k in out) return null
            out[k] = v
            ws()
            if (i >= json.length) return null
            val c = json[i++]
            if (c == '}') break
            if (c != ',') return null
        }
        ws()
        return if (i == json.length) out else null
    }

    /** A fresh random device name (labels are arbitrary; collisions retry). */
    fun freshName(): String {
        val r = ByteArray(2)
        java.security.SecureRandom().nextBytes(r)
        return "android-" + r.joinToString("") { "%02x".format(it) }
    }

    fun parseGrant(body: String): EnrollGrant? {
        val m = parseFlatObject(body) ?: return null
        val address = m["address"] ?: return null
        val psk = m["psk"] ?: return null
        if (!isValidIpv4(address)) return null
        // Adopted legacy peers carry an empty psk (none required, none issued).
        if (psk.isNotEmpty() && !EnrollmentValidator.isValidKey(psk)) return null
        return EnrollGrant(
            address = address,
            serverPubkey = m["server_pubkey"] ?: return null,
            endpoint = m["endpoint"] ?: return null,
            dns = m["dns"] ?: return null,
            psk = psk,
            allowedIps = m["allowed_ips"] ?: return null,
        )
    }

    fun isValidIpv4(s: String): Boolean {
        val parts = s.split(".")
        if (parts.size != 4) return false
        return parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true && p.isNotEmpty() }
    }

    /**
     * Fail-closed grant check: the grant must describe THIS service (the
     * pinned server cannot redirect us, but a misconfigured one must not
     * silently repoint the tunnel either).
     */
    fun checkGrant(grant: EnrollGrant): String? {
        if (grant.serverPubkey != ServiceConfig.SERVER_PUBLIC_KEY) return "server key mismatch"
        if (grant.endpoint != ServiceConfig.DISPLAY_ENDPOINT) return "endpoint mismatch"
        if (grant.dns != ServiceConfig.CLIENT_DNS) return "DNS mismatch"
        if (grant.allowedIps != ServiceConfig.ALLOWED_IPS) return "routing mismatch"
        return null
    }

    /** sha256 over DER bytes (for a cert, pass cert.publicKey.encoded). */
    fun spkiDigest(der: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(der)

    fun spkiPinB64(der: ByteArray): String =
        java.util.Base64.getEncoder().encodeToString(spkiDigest(der))
}

object EnrollmentClient {

    /**
     * Zero-touch provisioning: register [pubkey] under a fresh random name,
     * retrying with a new name on collision. Same pubkey always yields the
     * same server grant (idempotent), so retries never burn extra IPs.
     * Pure logic over [enroll]; the caller persists the grant.
     */
    fun autoEnroll(
        pubkey: String,
        target: EnrollTarget,
        timeoutMs: Int = 15_000,
        attempts: Int = 3,
    ): EnrollOutcome {
        var last: EnrollOutcome = EnrollOutcome.InvalidRequest("no attempts")
        repeat(attempts.coerceAtLeast(1)) {
            when (val r = enroll(target, EnrollmentCodec.freshName(), pubkey, timeoutMs)) {
                is EnrollOutcome.Conflict -> last = r // maybe our name; retry fresh
                else -> return r
            }
        }
        return last
    }

    /** Baked-in provisioning endpoint (non-secret bootstrap; see ServiceConfig). */
    fun defaultTarget(): EnrollTarget =
        EnrollTarget(ServiceConfig.ENROLL_HOST, ServiceConfig.ENROLL_PORT, ServiceConfig.ENROLL_PIN)

    fun pinnedTrustManager(pinB64: String): X509TrustManager {
        val expected = java.util.Base64.getDecoder().decode(pinB64.trim())
        require(expected.size == 32) { "pin is not a 32-byte digest" }
        return object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw CertificateException("client auth not used")
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) throw CertificateException("empty chain")
                val actual = EnrollmentCodec.spkiDigest(chain[0].publicKey.encoded)
                if (!MessageDigest.isEqual(expected, actual)) {
                    throw CertificateException("enrollment server pin mismatch")
                }
            }
        }
    }

    fun enroll(
        target: EnrollTarget,
        name: String,
        pubkey: String,
        timeoutMs: Int = 15_000,
    ): EnrollOutcome {
        if (!EnrollmentValidator.isValidName(name)) {
            return EnrollOutcome.InvalidRequest("bad device name")
        }
        if (!EnrollmentValidator.isValidKey(pubkey)) {
            return EnrollOutcome.InvalidRequest("bad public key")
        }
        if (!EnrollmentValidator.isValidPin(target.pinB64)) {
            return EnrollOutcome.Network("bad certificate pin")
        }
        return try {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(pinnedTrustManager(target.pinB64)), java.security.SecureRandom())
            val conn = URL("https://" + target.host + ":" + target.port + "/enroll")
                .openConnection() as HttpsURLConnection
            try {
                conn.sslSocketFactory = ctx.socketFactory
                // The SPKI pin verified by the TrustManager IS the server
                // identity (self-signed cert, no CA): hostname adds nothing.
                conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Cache-Control", "no-store")
                val body = EnrollmentCodec.buildRequest(name, pubkey).toByteArray(Charsets.UTF_8)
                conn.outputStream.use { it.write(body) }
                val code = conn.responseCode
                val text = try {
                    (if (code in 200..299) conn.inputStream else conn.errorStream)
                        ?.bufferedReader()?.readText().orEmpty()
                } catch (_: Exception) {
                    ""
                }
                when (code) {
                    200, 201 -> {
                        val grant = EnrollmentCodec.parseGrant(text)
                        if (grant == null) EnrollOutcome.InvalidGrant("unreadable server reply")
                        else {
                            val mismatch = EnrollmentCodec.checkGrant(grant)
                            if (mismatch != null) EnrollOutcome.InvalidGrant(mismatch)
                            else EnrollOutcome.Granted(grant)
                        }
                    }
                    403 -> EnrollOutcome.WindowClosed
                    409 -> EnrollOutcome.Conflict(errorOf(text))
                    429 -> EnrollOutcome.RateLimited(
                        conn.getHeaderField("Retry-After")?.toIntOrNull(),
                    )
                    503 -> EnrollOutcome.ServerFull
                    400 -> EnrollOutcome.InvalidRequest(errorOf(text))
                    else -> EnrollOutcome.ServerError(code)
                }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            val cert = generateSequence(e as Throwable?) { it.cause }
                .any { it is CertificateException }
            if (cert) EnrollOutcome.Network("server identity check failed")
            else EnrollOutcome.Network(e.message?.take(160) ?: e.javaClass.simpleName)
        }
    }

    private fun errorOf(body: String): String =
        EnrollmentCodec.parseFlatObject(body)?.get("error")?.take(64) ?: "rejected"
}
