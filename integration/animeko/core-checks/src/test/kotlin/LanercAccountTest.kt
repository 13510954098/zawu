// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlin.test.*

/** Static native wire fields with synthetic credentials. No real account or publication in CI. */
class LanercAccountTest {
    private val key = ByteArray(32) { it.toByte() }
    private val protocol = LanercProtocol(LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, emptyList()))
    private val origin = "https://example.invalid:443"
    private fun api(base: String = "https://example.invalid/", transport: suspend (LanercRequest) -> ByteArray) =
        LanercApi(protocol, { base }, { 1000 }, { "abc" }, transport)
    private val accepted = """{"code":201,"data":{}}""".encodeToByteArray()

    @Test fun `login uses native account pwd fields and never places password in URL or log representation`() = runTest {
        val result = api { request ->
            assertTrue(request.url.contains("/app/user/login?sign="))
            val body = Json.parseToJsonElement(request.body!!).jsonObject
            assertEquals(setOf("account", "pwd"), body.keys)
            assertEquals("fixture-password", body.getValue("pwd").jsonPrimitive.content)
            assertFalse(request.url.contains("fixture-password"))
            assertFalse(request.toString().contains("fixture-password"))
            assertNull(request.authorization)
            """{"code":201,"data":{"token":"native-fixture-token","user":{}}}""".encodeToByteArray()
        }.login("fixture-account", "fixture-password", origin)
        assertEquals(origin, result.origin)
        assertFalse(result.toString().contains("native-fixture-token"))
    }
    @Test fun `login backend must still match the origin explicitly confirmed by user`() = runTest {
        var requests = 0
        assertFails { api("https://changed.invalid/") { requests++; accepted }.login("account", "password", origin) }
        assertEquals(0, requests)
    }
    @Test fun `native comment publishes only native body fields and explicit raw Authorization header`() = runTest {
        api { request ->
            val body = Json.parseToJsonElement(request.body!!).jsonObject
            assertEquals(setOf("content", "vod_id", "parent_id"), body.keys)
            assertEquals(42L, body.getValue("vod_id").jsonPrimitive.long)
            assertEquals(0L, body.getValue("parent_id").jsonPrimitive.long)
            assertEquals("native-fixture-token", request.authorization)
            assertFalse(request.url.contains("native-fixture-token"))
            assertFalse(request.toString().contains("native-fixture-token"))
            accepted
        }.sendComment("42", "fixture comment", 0, LanercAccountCredential(origin, "native-fixture-token"))
    }
    @Test fun `barrage uses numeric video_url index seconds and native top position`() = runTest {
        api { request ->
            val body = Json.parseToJsonElement(request.body!!).jsonObject
            assertEquals(setOf("video_id", "video_url", "color", "second", "position", "content"), body.keys)
            assertEquals(3, body.getValue("video_url").jsonPrimitive.int)
            assertEquals(65L, body.getValue("second").jsonPrimitive.long)
            assertEquals(1, body.getValue("position").jsonPrimitive.int)
            accepted
        }.sendBarrage("42", 3, 65, "fixture barrage", true, LanercAccountCredential(origin, "fixture"))
    }
    @Test fun `account writes cannot cross backend origins and cannot use missing acknowledgements`() = runTest {
        var requests = 0
        assertFails { api("https://changed.invalid/") { requests++; accepted }.sendComment("42", "text", 0, LanercAccountCredential(origin, "fixture")) }
        assertEquals(0, requests)
        for (response in listOf("{}", "{\"code\":401}", "{\"code\":500}")) {
            assertFails { api { response.encodeToByteArray() }.sendComment("42", "text", 0, LanercAccountCredential(origin, "fixture")) }
        }
    }
    @Test fun `account header rejects injection and remains in a distinct source length delimited namespace`() {
        for (token in listOf("", " token", "token\r\nInjected: yes", "token\u0000", "x".repeat(16385))) {
            assertFails { LanercAccountCredential(origin, token) }
        }
        assertNotEquals(LanercStorageKeys.guest("s", origin), LanercStorageKeys.account("s", origin))
        assertFalse(LanercStorageKeys.account("s.child", origin).startsWith(LanercStorageKeys.accountPrefix("s")))
    }
}
