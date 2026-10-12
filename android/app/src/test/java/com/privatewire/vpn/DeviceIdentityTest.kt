package com.privatewire.vpn

import org.junit.Assert.*
import org.junit.Test

class DeviceIdentityTest {

    private fun keyOf(vararg bytes: Int): String {
        val raw = ByteArray(32) { i -> bytes[i % bytes.size].toByte() }
        return java.util.Base64.getEncoder().encodeToString(raw)
    }

    @Test fun deriveIsDeterministic() {
        val k = keyOf(1, 2, 3)
        assertEquals(DeviceIdentityManager.deriveAddress(k), DeviceIdentityManager.deriveAddress(k))
    }

    @Test fun deriveStaysInUsableRange() {
        for (i in 0 until 1000) {
            val addr = DeviceIdentityManager.deriveAddress(keyOf(i, i * 7 + 1, i * 13 + 5))
            val last = addr.substringAfterLast(".").toInt()
            assertTrue("out of range: $addr", last in 3..254)
            assertTrue(addr.startsWith("10.66.66."))
        }
    }

    @Test fun deriveNeverIssuesReservedAddresses() {
        for (i in 0 until 1000) {
            val addr = DeviceIdentityManager.deriveAddress(keyOf(i * 31 + 11, i + 3))
            assertFalse(addr.endsWith(".0"))
            assertFalse(addr.endsWith(".1"))
            assertFalse(addr.endsWith(".2"))
        }
    }

    @Test fun deriveRejectsNonKeys() {
        try {
            DeviceIdentityManager.deriveAddress("not-a-key")
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) { /* expected */ }
    }

    @Test fun distinctKeysSpreadAcrossRange() {
        val seen = (0 until 200).mapTo(HashSet()) { DeviceIdentityManager.deriveAddress(keyOf(it, it + 99)) }
        assertTrue("suspicious clustering: only ${seen.size} distinct", seen.size > 100)
    }
}
