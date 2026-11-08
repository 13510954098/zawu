// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.*
import java.io.File
import javax.crypto.AEADBadTagException
import kotlin.io.encoding.Base64
import kotlin.test.*

class LanercProtocolTest {
    @Test fun `native signature covers Uri path not authority or query`() {
        val first = protocol().sign("https://one.invalid/app/health?a=1", 1700000000, "abc")
        assertEquals(first, protocol().sign("https://two.invalid:8443/app/health?a=2", 1700000000, "abc"))
        assertNotEquals(first, protocol().sign("https://one.invalid/app/config?a=1", 1700000000, "abc"))
    }

    private val fixture = Json.parseToJsonElement(File(System.getProperty("lanerc.fixtures")).readText()).jsonObject
    private val key = ByteArray(32) { it.toByte() }
    private fun protocol(replacements: List<Pair<String, String>> = emptyList()) = LanercProtocol(
        LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, replacements),
    )
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.bytes(key: String) = Base64.decode(text(key))

    @Test fun `Dart signatures agree for seven canonical URIs`() {
        for (raw in fixture.getValue("uriSignatures").jsonArray) {
            val case = raw.jsonObject
            assertEquals(case.text("nativeSignaturePath"), LanercUri.signaturePath(case.text("canonicalUri")))
            assertEquals(case.text("sign"), protocol().sign(case.text("canonicalUri"), case.text("timestamp").toLong(), case.text("nonce")))
        }
    }

    @Test fun `Dart GCM envelope decrypts with JCE`() {
        val gcm = fixture.getValue("gcm").jsonObject
        assertContentEquals(gcm.bytes("plaintextProtoBase64"), protocol().decryptPlaybackEnvelope(gcm.bytes("encryptedEnvelopeBase64")))
    }

    @Test fun `Dart encrypted protobuf response decodes`() {
        val gcm = fixture.getValue("gcm").jsonObject
        val result = protocol().decodePlayResponse(gcm.bytes("responseProtoBase64"))
        assertEquals(gcm.text("expectedPlayUrl"), result.playUrl)
        assertTrue(result.encrypted)
        assertFalse(result.toString().contains("example.invalid"))
    }

    @Test fun `Dart ECB JSON decodes`() {
        val ecb = fixture.getValue("ecb").jsonObject
        assertEquals(Json.parseToJsonElement(ecb.text("expectedPlaintext")), protocol().decodeJsonTransport(ecb.text("ciphertextBase64")))
    }

    @Test fun `bootstrap uses separate primitive without JSON requirement`() {
        val ecb = fixture.getValue("ecb").jsonObject
        assertEquals(ecb.text("expectedPlaintext"), protocol().decodeBootstrapTxt(ecb.text("ciphertextBase64")))
    }

    @Test fun `GCM tampering fails authentication`() {
        val raw = fixture.getValue("gcm").jsonObject.bytes("encryptedEnvelopeBase64")
        raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
        assertFailsWith<AEADBadTagException> { protocol().decryptPlaybackEnvelope(raw) }
    }

    @Test fun `bad inputs fail without leaking transport text`() {
        assertFailsWith<IllegalArgumentException> { protocol().sign("https://example.invalid", -1, "abc") }
        assertFailsWith<IllegalArgumentException> { protocol().sign("https://example.invalid", 1, "ABC") }
        assertFailsWith<IllegalArgumentException> { protocol().decryptPlaybackEnvelope(ByteArray(27)) }
        val error = assertFailsWith<IllegalArgumentException> { protocol().decodeJsonTransport("private-response-marker") }
        assertFalse(error.toString().contains("private-response-marker"))
    }

    @Test fun `secrets are copied and redacted`() {
        val material = LanercSecrets("fixture-suffix-17", key, key, key, emptyList())
        key.fill(0)
        assertContentEquals(ByteArray(32) { it.toByte() }, material.playbackKey())
        val exposed = material.playbackKey()
        exposed.fill(0)
        assertContentEquals(ByteArray(32) { it.toByte() }, material.playbackKey())
        assertFalse(material.toString().contains("fixture-suffix-17"))
    }

    private fun varint(number: Long): ByteArray {
        var value = number
        val result = mutableListOf<Byte>()
        while (value and -128L != 0L) {
            result += ((value and 127) or 128).toByte()
            value = value ushr 7
        }
        result += value.toByte()
        return result.toByteArray()
    }
    private fun field(number: Int, bytes: ByteArray) = varint((number * 8 + 2).toLong()) + varint(bytes.size.toLong()) + bytes

    @Test fun `wire duplicates unknown fields and wrong types match protobuf semantics`() {
        val msg = byteArrayOf(8) + varint(200) + field(1, "wrong-type".encodeToByteArray()) +
            field(99, byteArrayOf(1, 2)) + byteArrayOf(24, 1, 24, 0) + field(4, byteArrayOf(9)) + field(4, byteArrayOf(7))
        val outer = LanercWire.response(msg)
        assertEquals(200, outer.code)
        assertFalse(outer.encrypted)
        assertContentEquals(byteArrayOf(7), outer.data)
        assertEquals("last", LanercWire.playUrl(field(1, "first".encodeToByteArray()) + field(1, "last".encodeToByteArray())))
    }

    @Test fun `signed int32 and boolean varints decode`() {
        assertEquals(-1, LanercWire.response(byteArrayOf(8) + varint(-1)).code)
        assertTrue(LanercWire.response(byteArrayOf(24) + varint(-1)).encrypted)
    }

    @Test fun `malformed wire framing is rejected`() {
        for (raw in listOf(byteArrayOf(0), byteArrayOf(10, 3, 1), byteArrayOf(8, -128),
            byteArrayOf(11), byteArrayOf(15), byteArrayOf(8) + ByteArray(10) { -128 },
            byteArrayOf(8) + ByteArray(9) { -1 } + byteArrayOf(2))) {
            assertFails { LanercWire.response(raw) }
        }
    }

    @Test fun `blank URL and failure status do not become playable`() {
        assertFails { protocol().decodePlayResponse(byteArrayOf(8) + varint(200) + field(4, field(1, " ".encodeToByteArray()))) }
        assertFails { protocol().decodePlayResponse(byteArrayOf(8) + varint(403)) }
    }

    @Test fun `comments path follows original APK not cleanroom`() {
        assertEquals("app/chat/comment", LanercEndpoints.COMMENTS)
    }
}
