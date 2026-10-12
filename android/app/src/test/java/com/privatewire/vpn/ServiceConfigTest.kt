package com.privatewire.vpn

import org.junit.Assert.*
import org.junit.Test

class ServiceConfigTest {

    private val priv = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    private val pub = "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws="
    private val id = DeviceIdentity(priv, pub, "10.66.66.9")

    @Test fun buildConfigPassesValidator() {
        assertTrue(WgConfigValidator.validate(ServiceConfig.buildConfig(id)) is WgConfigValidator.Result.Ok)
    }

    @Test fun buildConfigCarriesServiceParams() {
        val conf = ServiceConfig.buildConfig(id)
        assertTrue(conf.contains("Endpoint = 129.80.41.146:51820"))
        assertTrue(conf.contains("Address = 10.66.66.9/32"))
        assertTrue(conf.contains("DNS = 10.66.66.1"))
        assertTrue(conf.contains("AllowedIPs = 0.0.0.0/0"))
        assertTrue(conf.contains("PersistentKeepalive = 25"))
        assertTrue(conf.contains("PublicKey = " + ServiceConfig.SERVER_PUBLIC_KEY))
        // No preshared key in the dev setup: server peer has none either.
        assertFalse(conf.contains("PresharedKey"))
    }

    @Test fun summarizeExtractsEndpointAndIp() {
        val (ep, ip) = WgConfigValidator.summarize(ServiceConfig.buildConfig(id))
        assertEquals("129.80.41.146:51820", ep)
        assertEquals("10.66.66.9/32", ip)
    }

    @Test fun adoptedGrantWithoutPskBuildsValidConfig() {
        val conf = ServiceConfig.buildConfig(id, "")
        assertTrue(WgConfigValidator.validate(conf) is WgConfigValidator.Result.Ok)
        assertFalse(conf.contains("PresharedKey"))
        assertTrue(conf.contains("Address = 10.66.66.9/32"))
    }

    @Test fun enrolledGrantWithPskBuildsValidConfig() {
        val conf = ServiceConfig.buildConfig(id, priv)
        assertTrue(WgConfigValidator.validate(conf) is WgConfigValidator.Result.Ok)
        assertTrue(conf.contains("PresharedKey = $priv"))
    }

    @Test fun localProvisioningMatchesDerivation() {
        val rec = LocalDeterministicProvisioning.provision(pub)
        assertEquals(DeviceIdentityManager.deriveAddress(pub), rec.clientAddress)
    }
}
