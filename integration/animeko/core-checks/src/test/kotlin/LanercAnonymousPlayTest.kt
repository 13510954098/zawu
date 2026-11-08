// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlin.test.*

class LanercAnonymousPlayTest {
    private val key = ByteArray(32) { it.toByte() }
    private val protocol = LanercProtocol(LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, emptyList()))
    private fun api(transport: suspend (LanercRequest) -> ByteArray) =
        LanercApi(protocol, { "https://example.invalid/" }, { 1000 }, { "abc" }, transport)

    @Test fun anonymousPlayNeedsNeitherAccountNorGuestCredential() = runTest {
        val url = "http://media.example.com/video.m3u8"
        val result = api { request ->
            assertTrue(request.url.contains("/app/v2/play?sign="))
            assertFalse(request.url.contains("/guest/"))
            assertNull(request.authorization)
            assertTrue(request.protobuf)
            assertEquals(buildJsonObject { put("resource_id", "native-resource") }, Json.parseToJsonElement(request.body!!))
            val bytes = url.encodeToByteArray()
            val inner = byteArrayOf(0x0a, bytes.size.toByte()) + bytes
            byteArrayOf(0x08, 0xc8.toByte(), 0x01, 0x22, inner.size.toByte()) + inner
        }.playAnonymous("native-resource")
        assertEquals(url, result.playUrl)
        assertFalse(result.toString().contains(url))
    }

    @Test fun invalidResourceDoesNotSendRequests() = runTest {
        var requests = 0
        assertFails { api { requests++; byteArrayOf() }.playAnonymous("bad/resource") }
        assertEquals(0, requests)
    }

    @Test fun mediaHttpAllowanceDoesNotWeakenApiHttpsOrPrivateHostPolicy() {
        assertTrue(publicMediaUrl("http://media.example.com/video.m3u8"))
        assertTrue(publicMediaUrl("https://media.example.com/video.m3u8"))
        assertFalse(publicHttpsUrl("http://api.example.com/"))
        for (url in listOf("http://127.0.0.1/a", "http://localhost/a", "http://media.local/a", "http://user:pass@media.example.com/a", "file:///a", "http://media.example.com/a\n")) {
            assertFalse(publicMediaUrl(url))
        }
    }
}
