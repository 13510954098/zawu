// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.io.encoding.Base64

/** Platform implementation must authenticate GCM before returning plaintext. */
interface LanercCrypto {
    fun md5(input: ByteArray): String
    fun decryptGcm(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray): ByteArray
    fun decryptEcbPkcs7(key: ByteArray, ciphertext: ByteArray): ByteArray
}

/** Kept separate from exportable source definitions. No secret-bearing toString. */
class LanercSecrets(
    suffix: String,
    playbackKey: ByteArray,
    jsonKey: ByteArray,
    bootstrapKey: ByteArray,
    replacements: List<Pair<String, String>>,
) {
    internal val suffix = suffix
    private val playback = playbackKey.copyOf()
    private val json = jsonKey.copyOf()
    private val bootstrap = bootstrapKey.copyOf()
    internal val replacements = replacements.toList()
    internal fun playbackKey() = playback.copyOf()
    internal fun jsonKey() = json.copyOf()
    internal fun bootstrapKey() = bootstrap.copyOf()
    init {
        require(suffix.length == 17) { "Unexpected signing suffix length" }
        require(listOf(playbackKey, jsonKey, bootstrapKey).all { it.size == 32 }) { "Expected AES-256 keys" }
        require(replacements.all { it.first.length == 1 && it.second.length == 1 }) { "Invalid replacement table" }
    }
    override fun toString(): String = "LanercSecrets(REDACTED)"
}

/** Known paths from the original APK. Not the cleanroom API contract. */
object LanercEndpoints {
    const val SEARCH = "app/vod/search"
    const val DETAIL_PREFIX = "app/v2/vod/"
    const val CAPTCHA = "app/v2/guest/captcha"
    const val GUEST_CREDENTIAL = "app/v2/guest/credential"
    const val GUEST_PLAY = "app/v2/guest/play"
    const val COMMENTS = "app/chat/comment"
    const val DANMAKU = "app/chat/barragev2"
    const val SEND_DANMAKU = "app/chat/sendbarrage"
}

/** Offline protocol primitives. The canonical URI must be computed before adding sign. */
class LanercProtocol(private val crypto: LanercCrypto, private val secrets: LanercSecrets) {
    fun sign(canonicalUri: String, timestampSeconds: Long, nonce: String): String {
        require(timestampSeconds >= 0) { "Invalid timestamp" }
        require(Regex("[a-z]{3}").matches(nonce)) { "Invalid nonce" }
        val path = LanercUri.signaturePath(canonicalUri)
        val digest = crypto.md5("$path@$timestampSeconds@$nonce${secrets.suffix}".encodeToByteArray())
        require(Regex("[a-f0-9]{32}").matches(digest)) { "Invalid digest implementation" }
        return "$timestampSeconds-$nonce-$digest"
    }

    fun decryptPlaybackEnvelope(envelope: ByteArray): ByteArray {
        require(envelope.size in 28..MAX_BYTES) { "Invalid GCM envelope size" }
        return crypto.decryptGcm(secrets.playbackKey(), envelope.copyOfRange(0, 12), envelope.copyOfRange(12, envelope.size))
    }

    /** ECB is unauthenticated, including when padding and JSON parsing succeed. */
    fun decodeJsonTransport(encoded: String): JsonElement {
        require(encoded.length <= MAX_BYTES) { "Response size limit" }
        var transformed = encoded
        for ((from, to) in secrets.replacements) transformed = transformed.replace(from, to)
        return try {
            Json.parseToJsonElement(decryptEcb(transformed, secrets.jsonKey()).decodeToString(throwOnInvalidSequence = true))
        } catch (_: Exception) {
            throw IllegalArgumentException("Invalid encrypted JSON response")
        }
    }

    fun decodeBootstrapTxt(encoded: String): String =
        decryptEcb(encoded, secrets.bootstrapKey()).decodeToString(throwOnInvalidSequence = true)

    private fun decryptEcb(encoded: String, key: ByteArray): ByteArray {
        require(encoded.length <= MAX_BYTES) { "Response size limit" }
        val raw = Base64.decode(encoded)
        require(raw.isNotEmpty() && raw.size % 16 == 0) { "Invalid ECB block framing" }
        return crypto.decryptEcbPkcs7(key, raw)
    }

    /** Does not fetch a media URL or interpret an HTTP/JSON wrapper as protobuf. */
    fun decodePlayResponse(raw: ByteArray): LanercPlayResult {
        val outer = LanercWire.response(raw)
        require(outer.code == 200) { "Playback response was not successful" }
        val inner = if (outer.encrypted) decryptPlaybackEnvelope(outer.data) else outer.data
        val url = LanercWire.playUrl(inner).trim()
        require(url.isNotEmpty()) { "Playback response contains no URL" }
        return LanercPlayResult(url, outer.encrypted)
    }

    companion object { const val MAX_BYTES = 16 * 1024 * 1024 }
}

/** toString omits signed query strings and other playback tokens. */
class LanercPlayResult(val playUrl: String, val encrypted: Boolean) {
    override fun toString(): String = "LanercPlayResult(encrypted=$encrypted, playUrl=REDACTED)"
}
