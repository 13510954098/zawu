// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.test.*

class LanercDynamicBootstrapTest {
    private val key = ByteArray(32) { it.toByte() }
    private val protocol = LanercProtocol(LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, emptyList()))
    private val plan = LanercBootstrapPlan("test", listOf("source.example.invalid"), listOf("https://dns.example.invalid/resolve"))
    private fun encrypted(url: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return Base64.encode(cipher.doFinal(url.encodeToByteArray()))
    }
    private fun response(url: String = "https://backend.example.invalid/", ttl: Int = 60, invalidFirst: Boolean = false): String =
        buildJsonObject {
            put("Status", 0)
            putJsonArray("Answer") {
                if (invalidFirst) addJsonObject {
                    put("name", "source.example.invalid."); put("type", 16); put("TTL", ttl); put("data", "invalid-base64-marker")
                }
                addJsonObject {
                    put("name", "source.example.invalid."); put("type", 16); put("TTL", ttl)
                    val encoded = encrypted(url)
                    put("data", "\"${encoded.take(12)}\" \"${encoded.drop(12)}\"")
                }
            }
        }.toString()

    @Test fun `discovery decodes TXT chunks and respects cache TTL`() = runTest {
        var now = 0L
        var calls = 0
        val resolver = LanercDynamicBootstrap(plan, protocol, { now }, { calls++; response() })
        assertEquals("https://backend.example.invalid/", resolver.resolve().baseUrl)
        assertEquals(1, calls)
        now = 59_999
        resolver.resolve()
        assertEquals(1, calls)
        now = 60_000
        resolver.resolve()
        assertEquals(2, calls)
    }

    @Test fun `expired cache cannot mask failed discovery`() = runTest {
        var now = 0L
        val resolver = LanercDynamicBootstrap(plan, protocol, { now }, { if (now == 0L) response() else error("private-failure-marker") })
        resolver.resolve()
        now = 60_001
        val error = assertFailsWith<IllegalStateException> { resolver.resolve() }
        assertFalse(error.toString().contains("private-failure-marker"))
    }

    @Test fun `bad TXT does not hide later valid TXT`() = runTest {
        val resolver = LanercDynamicBootstrap(plan, protocol, { 0 }, { response(invalidFirst = true) })
        assertEquals("https://backend.example.invalid/", resolver.resolve().baseUrl)
    }

    @Test fun `invalid backend does not become a usable source`() = runTest {
        for (url in listOf("http://example.invalid/", "https://user:password@example.invalid/", "https://127.0.0.1/", "https://0x7f.0.0.1/", "https://[::1]/", "https://example.local/", "https://example.invalid/#secret")) {
            val resolver = LanercDynamicBootstrap(plan, protocol, { 0 }, { response(url) })
            assertFailsWith<IllegalStateException> { resolver.resolve() }
        }
    }

    @Test fun `simultaneous resolution shares one in flight query`() = runTest {
        var calls = 0
        val resolver = LanercDynamicBootstrap(plan, protocol, { 0 }, { calls++; delay(5); response() })
        val a = async { resolver.resolve() }
        val b = async { resolver.resolve() }
        assertEquals(a.await().baseUrl, b.await().baseUrl)
        assertEquals(1, calls)
    }

    @Test fun `zero TTL forces refresh and invalidation clears cache`() = runTest {
        var calls = 0
        val resolver = LanercDynamicBootstrap(plan, protocol, { 0 }, { calls++; response(ttl = 0) })
        resolver.resolve(); resolver.resolve()
        assertEquals(2, calls)
        val cached = LanercDynamicBootstrap(plan, protocol, { 0 }, { calls++; response() })
        cached.resolve(); cached.invalidate(); cached.resolve()
        assertEquals(4, calls)
    }

    @Test fun `built in definition is dynamic rather than a static backend`() {
        val builtIn = LanercBootstrapPlan.builtIn()
        assertEquals("dohx.lanerc.moe", builtIn.domains.first())
        assertTrue(builtIn.providers.isNotEmpty())
        assertFalse(builtIn.providers.any { "yyghk" in it })
    }
}
