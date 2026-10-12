package com.privatewire.vpn

import org.junit.Assert.*
import org.junit.Test

class WgConfigValidatorTest {

    private val good = """
        [Interface]
        PrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
        Address = 10.8.0.2/32
        DNS = 10.8.0.1

        [Peer]
        PublicKey = CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=
        PresharedKey = ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExM=
        AllowedIPs = 0.0.0.0/0
        Endpoint = 203.0.113.10:51820
        PersistentKeepalive = 25
    """.trimIndent()

    @Test fun acceptsValidFullTunnel() {
        assertTrue(WgConfigValidator.validate(good) is WgConfigValidator.Result.Ok)
    }

    @Test fun rejectsEmpty() {
        assertTrue(WgConfigValidator.validate("") is WgConfigValidator.Result.Err)
    }

    @Test fun rejectsMissingPeer() {
        val noPeer = good.lines().takeWhile { it.trim() != "[Peer]" }.joinToString("\n")
        val r = WgConfigValidator.validate(noPeer)
        assertTrue(r is WgConfigValidator.Result.Err)
    }

    @Test fun rejectsBadPrivateKey() {
        val bad = good.replace("PrivateKey = BwcH", "PrivateKey = not-a-key")
        assertTrue(WgConfigValidator.validate(bad) is WgConfigValidator.Result.Err)
    }

    @Test fun rejectsMissingEndpoint() {
        val bad = good.lines().filter { !it.trim().startsWith("Endpoint") }.joinToString("\n")
        assertTrue(WgConfigValidator.validate(bad) is WgConfigValidator.Result.Err)
    }

    @Test fun acceptsSplitTunnel() {
        val split = good.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.8.0.0/24")
        assertTrue(WgConfigValidator.validate(split) is WgConfigValidator.Result.Ok)
    }

    @Test fun acceptsConfigWithoutPresharedKey() {
        val noPsk = good.lines().filter { !it.trim().startsWith("PresharedKey") }.joinToString("\n")
        assertTrue(WgConfigValidator.validate(noPsk) is WgConfigValidator.Result.Ok)
    }

    @Test fun summarizeExtractsEndpointAndIp() {
        val (ep, ip) = WgConfigValidator.summarize(good)
        assertEquals("203.0.113.10:51820", ep)
        assertEquals("10.8.0.2/32", ip)
    }

    @Test fun rejectsUnknownKeys() {
        val bad = good + "\nEvilKey = 1\n"
        // EvilKey sits in [Peer] section -> rejected
        assertTrue(WgConfigValidator.validate(bad) is WgConfigValidator.Result.Err)
    }
}
