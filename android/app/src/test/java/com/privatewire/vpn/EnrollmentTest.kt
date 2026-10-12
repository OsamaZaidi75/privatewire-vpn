package com.privatewire.vpn

import org.junit.Assert.*
import org.junit.Test

class EnrollmentTest {

    private fun keyOf(seed: Int): String {
        val raw = ByteArray(32) { i -> ((seed * 37 + i * 11) and 0xFF).toByte() }
        raw[31] = ((seed * 13) and 0xF0).toByte()
        val k = java.util.Base64.getEncoder().encodeToString(raw)
        assertTrue(EnrollmentValidator.isValidKey(k))
        return k
    }

    private val pin = java.util.Base64.getEncoder()
        .encodeToString(ByteArray(32) { it.toByte() })

    // ---------- validation ----------

    @Test fun names() {
        assertTrue(EnrollmentValidator.isValidName("mom-phone_2"))
        assertFalse(EnrollmentValidator.isValidName(""))
        assertFalse(EnrollmentValidator.isValidName("my phone"))
        assertFalse(EnrollmentValidator.isValidName("../x"))
        assertFalse(EnrollmentValidator.isValidName("a".repeat(33)))
        assertTrue(EnrollmentValidator.isValidName("a".repeat(32)))
    }

    @Test fun keys() {
        assertTrue(EnrollmentValidator.isValidKey(keyOf(3)))
        assertFalse(EnrollmentValidator.isValidKey("junk"))
        assertFalse(EnrollmentValidator.isValidKey(keyOf(3) + "x"))
    }

    @Test fun pins() {
        assertTrue(EnrollmentValidator.isValidPin(pin))
        assertFalse(EnrollmentValidator.isValidPin("junk"))
        assertFalse(EnrollmentValidator.isValidPin(""))
    }

    // ---------- enrollment codes ----------

    @Test fun parseFullCode() {
        val t = EnrollmentCodec.parseCode(
            "pw-enroll://203.0.113.10:8443#$pin", "h", 1)
        assertEquals(EnrollTarget("203.0.113.10", 8443, pin), t)
    }

    @Test fun parseBarePinUsesDefaults() {
        val t = EnrollmentCodec.parseCode(pin, "203.0.113.10", 8443)
        assertEquals(EnrollTarget("203.0.113.10", 8443, pin), t)
    }

    @Test fun parseCodeRejects() {
        assertNull(EnrollmentCodec.parseCode("", "h", 1))
        assertNull(EnrollmentCodec.parseCode("https://h:1#$pin", "h", 1))
        assertNull(EnrollmentCodec.parseCode("pw-enroll://h:1#junk", "h", 1))
        assertNull(EnrollmentCodec.parseCode("pw-enroll://h:99999#$pin", "h", 1))
        assertNull(EnrollmentCodec.parseCode("pw-enroll://h#$pin", "h", 1))
        assertNull(EnrollmentCodec.parseCode("junk", "h", 1))
        assertNull(EnrollmentCodec.parseCode(pin, "", 8443))
    }

    // ---------- flat JSON ----------

    @Test fun requestRoundTrips() {
        val body = EnrollmentCodec.buildRequest("a\"b\\c", keyOf(5))
        val m = EnrollmentCodec.parseFlatObject(body)
        assertNotNull(m)
        assertEquals("a\"b\\c", m!!["name"])
        assertEquals(keyOf(5), m["pubkey"])
    }

    @Test fun flatParserRejects() {
        assertNull(EnrollmentCodec.parseFlatObject(""))
        assertNull(EnrollmentCodec.parseFlatObject("{not json}"))
        assertNull(EnrollmentCodec.parseFlatObject("{\"a\":1}"))
        assertNull(EnrollmentCodec.parseFlatObject("{\"a\":\"x\",\"a\":\"y\"}"))
        assertNull(EnrollmentCodec.parseFlatObject("{\"a\":\"x\"} trailing"))
        assertNull(EnrollmentCodec.parseFlatObject("{\"a\":\"x\",}"))
    }

    // ---------- grants ----------

    private fun goodGrant() = EnrollGrant(
        "10.66.66.9", ServiceConfig.SERVER_PUBLIC_KEY,
        ServiceConfig.DISPLAY_ENDPOINT, ServiceConfig.CLIENT_DNS,
        keyOf(9), ServiceConfig.ALLOWED_IPS,
    )

    @Test fun grantRoundTrips() {
        val g = goodGrant()
        val body = "{\"address\":\"${g.address}\"," +
            "\"server_pubkey\":\"${g.serverPubkey}\"," +
            "\"endpoint\":\"${g.endpoint}\",\"dns\":\"${g.dns}\"," +
            "\"psk\":\"${g.psk}\",\"allowed_ips\":\"${g.allowedIps}\"}"
        assertEquals(g, EnrollmentCodec.parseGrant(body))
    }

    @Test fun grantRejectsBadAddressOrPsk() {
        assertNull(EnrollmentCodec.parseGrant(
            "{\"address\":\"999.1.1.1\",\"psk\":\"${keyOf(1)}\"," +
                "\"server_pubkey\":\"x\",\"endpoint\":\"y\",\"dns\":\"z\",\"allowed_ips\":\"w\"}"))
        assertNull(EnrollmentCodec.parseGrant("{\"address\":\"10.0.0.5\"}"))
        assertNull(EnrollmentCodec.parseGrant(
            "{\"address\":\"10.0.0.5\",\"psk\":\"junk\"," +
                "\"server_pubkey\":\"x\",\"endpoint\":\"y\",\"dns\":\"z\",\"allowed_ips\":\"w\"}"))
    }

    @Test fun grantAcceptsEmptyPskForAdoptedPeers() {
        val g = goodGrant().copy(psk = "")
        val body = "{\"address\":\"${g.address}\"," +
            "\"server_pubkey\":\"${g.serverPubkey}\"," +
            "\"endpoint\":\"${g.endpoint}\",\"dns\":\"${g.dns}\"," +
            "\"psk\":\"\",\"allowed_ips\":\"${g.allowedIps}\"}"
        assertEquals(g, EnrollmentCodec.parseGrant(body))
    }

    @Test fun freshNamesAreValidAndVaried() {
        val seen = (1..50).mapTo(HashSet()) { EnrollmentCodec.freshName() }
        assertTrue(seen.all { EnrollmentValidator.isValidName(it) })
        assertTrue("names should vary", seen.size > 40)
    }

    @Test fun grantCheckFailsClosed() {
        assertNull(EnrollmentCodec.checkGrant(goodGrant()))
        assertNotNull(EnrollmentCodec.checkGrant(goodGrant().copy(serverPubkey = keyOf(8))))
        assertNotNull(EnrollmentCodec.checkGrant(goodGrant().copy(endpoint = "1.2.3.4:5")))
        assertNotNull(EnrollmentCodec.checkGrant(goodGrant().copy(dns = "8.8.8.8")))
        assertNotNull(EnrollmentCodec.checkGrant(goodGrant().copy(allowedIps = "10.0.0.0/8")))
    }

    @Test fun ipv4Check() {
        assertTrue(EnrollmentCodec.isValidIpv4("10.66.66.9"))
        assertFalse(EnrollmentCodec.isValidIpv4("10.66.66.256"))
        assertFalse(EnrollmentCodec.isValidIpv4("::1"))
        assertFalse(EnrollmentCodec.isValidIpv4("10.66.66"))
    }

    @Test fun spkiDigestKnownAnswer() {
        // sha256("abc") — independent test vector, not from the impl.
        val got = EnrollmentCodec.spkiDigest("abc".toByteArray())
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            got.joinToString("") { "%02x".format(it) },
        )
    }

    @Test fun enrollRejectsBadInputWithoutNetwork() {
        val t = EnrollTarget("127.0.0.1", 9, pin)
        assertTrue(EnrollmentClient.enroll(t, "bad name!", keyOf(1))
            is EnrollOutcome.InvalidRequest)
        assertTrue(EnrollmentClient.enroll(t, "ok-name", "junk")
            is EnrollOutcome.InvalidRequest)
    }
}
