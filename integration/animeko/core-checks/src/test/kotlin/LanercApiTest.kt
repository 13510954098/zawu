// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import java.io.File
import kotlin.io.encoding.Base64
import kotlin.test.*

class LanercApiTest {
    private val key = ByteArray(32) { it.toByte() }
    private val protocol = LanercProtocol(LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, emptyList()))
    private val fixture = Json.parseToJsonElement(File(System.getProperty("lanerc.fixtures")).readText()).jsonObject

    @Test fun `Kotlin URI and Ktor roundtrip agree with seven Dart fixtures`() {
        for (raw in fixture.getValue("uriSignatures").jsonArray) {
            val case = raw.jsonObject
            val actual = LanercUri.canonical(case.getValue("baseUrl").jsonPrimitive.content,
                case.getValue("path").jsonPrimitive.content, case.getValue("query").jsonObject)
            assertEquals(case.getValue("canonicalUri").jsonPrimitive.content, actual)
            val signed = LanercUri.signed(actual, case.getValue("sign").jsonPrimitive.content)
            assertEquals(signed, URLBuilder().takeFrom(signed).buildString())
        }
    }

    @Test fun `existing encoded signature is rejected before signing`() {
        assertFails { LanercUri.canonical("https://example.invalid/", "x?%73ign=old") }
        assertFails { LanercUri.canonical("https://example.invalid/", "x", mapOf("sign" to JsonPrimitive("old"))) }
    }

    @Test fun `captcha and credential exchange retain origin and string selected field`() = runTest {
        val calls = mutableListOf<LanercRequest>()
        val api = LanercApi(protocol, { "https://example.invalid/" }, { 1000 }, { "abc" }) { request ->
            calls += request
            if (calls.size == 1) """{"code":200,"data":{"challenge_id":"test","image":"aGVsbG8=","option_count":3,"expires_in":60}}""".encodeToByteArray()
            else """{"code":200,"data":{"guest_credential":"private-token-marker","expires_in":120}}""".encodeToByteArray()
        }
        val captcha = api.captcha()
        assertEquals("{}", calls.single().body) // APK 0x920050..0x920074 -> Dio POST with an empty JSON map.
        val credential = api.exchange(captcha, 2)
        assertEquals("https://example.invalid:443", credential.origin)
        assertEquals(121000L, credential.expiresAtMillis)
        assertEquals("2", Json.parseToJsonElement(calls.last().body!!).jsonObject.getValue("selected").jsonPrimitive.content)
        assertTrue(Json.parseToJsonElement(calls.last().body!!).jsonObject.getValue("selected").jsonPrimitive.isString)
        assertFalse(credential.toString().contains("private-token-marker"))
        assertFalse(calls.last().toString().contains("challenge_id"))
        // Native selected is a string; no production evidence fixes the image numbering base.
        api.exchange(captcha, 0)
        assertEquals("0", Json.parseToJsonElement(calls.last().body!!).jsonObject.getValue("selected").jsonPrimitive.content)
        val beforeInvalid = calls.size
        assertFails { api.exchange(captcha, -1) }
        assertFails { api.exchange(captcha, captcha.optionCount + 1) }
        assertEquals(beforeInvalid, calls.size)
    }

    @Test fun `rotated backend and expired credentials never reach transport`() = runTest {
        var calls = 0
        val api = LanercApi(protocol, { "https://other.invalid/" }, { 1000 }, { "abc" }) { calls++; error("Must not execute") }
        assertFails { api.play("id", LanercGuestCredential("https://example.invalid:443", "private", 2000)) }
        assertFails { api.play("id", LanercGuestCredential("https://other.invalid:443", "private", 1000)) }
        assertFails { api.exchange(LanercCaptcha("https://example.invalid:443", "id", "image", 3, 2000), 1) }
        assertEquals(0, calls)
    }

    @Test fun `play sends native body and decodes independent Dart protobuf`() = runTest {
        var captured: LanercRequest? = null
        val gcm = fixture.getValue("gcm").jsonObject
        val api = LanercApi(protocol, { "https://example.invalid/" }, { 1000 }, { "abc" }) {
            captured = it
            Base64.decode(gcm.getValue("responseProtoBase64").jsonPrimitive.content)
        }
        val result = api.play("resource_1", LanercGuestCredential("https://example.invalid:443", "private-token-marker", 2000))
        assertEquals(gcm.getValue("expectedPlayUrl").jsonPrimitive.content, result.playUrl)
        val request = requireNotNull(captured)
        assertTrue(request.protobuf)
        assertTrue(request.url.contains("app/v2/guest/play?sign="))
        val body = Json.parseToJsonElement(request.body!!).jsonObject
        assertEquals("resource_1", body.getValue("resource_id").jsonPrimitive.content)
        assertEquals("private-token-marker", body.getValue("guest_credential").jsonPrimitive.content)
        assertFalse(request.url.contains("private-token-marker"))
        assertFalse(request.toString().contains("private-token-marker"))
    }

    @Test fun `absolute endpoint override cannot send authenticated body cross origin`() = runTest {
        var calls = 0
        val api = LanercApi(protocol, { "https://example.invalid/" }, { 1000 }, { "abc" }) { calls++; byteArrayOf() }
        assertFails { api.json("https://other.invalid/x") }
        assertEquals(0, calls)
    }

    @Test fun `native catalog uses APK keys and preserves all lines`() {
        val search = Json.parseToJsonElement("""{"code":200,"data":{"search_vods":[{"id":123,"vod_name":"Example"}]}}""")
        assertEquals(LanercSubject("123", "Example"), LanercCatalog.search(search).single())
        val detail = Json.parseToJsonElement("""{"video_play_list":[{"player":"line1","name":"Line","video":[{"resource_id":"one","title":"第1集"},{"resource_id":"two","title":"第2集"}]}]}""")
        assertEquals(2, LanercCatalog.lines(detail).single().episodes.size)
        assertFails { LanercCatalog.search(Json.parseToJsonElement("""{"items":[]}""")) }
        assertFails { LanercCatalog.search(Json.parseToJsonElement("""{"code":403,"data":{"search_vods":[]}}""")) }
    }
}
