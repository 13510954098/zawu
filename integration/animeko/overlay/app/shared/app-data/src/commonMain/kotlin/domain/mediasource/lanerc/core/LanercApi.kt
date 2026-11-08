// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.*

/** Transport implementations must disable redirects and cookies and must not log request URLs/bodies. */
class LanercRequest(val url: String, val body: String?, val protobuf: Boolean) {
    override fun toString() = "LanercRequest(REDACTED)"
}
class LanercCaptcha(val origin: String, val challengeId: String, val image: String, val optionCount: Int, val expiresAtMillis: Long) {
    override fun toString() = "LanercCaptcha(REDACTED)"
}
class LanercGuestCredential(val origin: String, val value: String, val expiresAtMillis: Long) {
    override fun toString() = "LanercGuestCredential(REDACTED)"
}

/** API primitives for one source. Credentials are origin-bound and never exported with source definitions. */
class LanercApi(
    private val protocol: LanercProtocol,
    private val resolveBackend: suspend () -> String,
    private val nowMillis: () -> Long,
    private val nonce: () -> String,
    private val transport: suspend (LanercRequest) -> ByteArray,
) {
    suspend fun backend(): String = resolveBackend().also { require(publicHttpsUrl(it)) }
    suspend fun json(path: String, query: Map<String, JsonElement> = emptyMap()): JsonElement =
        jsonAt(backend(), path, query)

    private suspend fun request(base: String, path: String, query: Map<String, JsonElement>, body: JsonObject?, protobuf: Boolean): ByteArray {
        val canonical = LanercUri.canonical(base, path, query)
        // Absolute endpoint overrides must never forward a credential to another origin.
        require(LanercUri.origin(canonical) == LanercUri.origin(base)) { "Cross-origin API request rejected" }
        val sign = protocol.sign(canonical, nowMillis() / 1000, nonce())
        return transport(LanercRequest(LanercUri.signed(canonical, sign), body?.toString(), protobuf)).also {
            require(it.size <= LanercProtocol.MAX_BYTES) { "Response size limit" }
        }
    }

    private suspend fun jsonAt(base: String, path: String, query: Map<String, JsonElement> = emptyMap(), body: JsonObject? = null): JsonElement {
        val raw = request(base, path, query, body, false).decodeToString(throwOnInvalidSequence = true)
        fun decodeString(value: String): JsonElement = if (value.trimStart().startsWith('{') || value.trimStart().startsWith('['))
            Json.parseToJsonElement(value) else protocol.decodeJsonTransport(value)
        return try {
            val root = Json.parseToJsonElement(raw)
            when {
                root is JsonPrimitive && root.isString -> decodeString(root.content)
                root is JsonObject && root["data"] is JsonPrimitive && root.getValue("data").jsonPrimitive.isString ->
                    JsonObject(root + ("data" to decodeString(root.getValue("data").jsonPrimitive.content)))
                else -> root
            }
        } catch (_: Exception) {
            throw IllegalArgumentException("Unsupported or invalid Lanerc JSON transport")
        }
    }

    suspend fun barrages(vid: String, vodIndex: Int): List<LanercBarrage> {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(vid) && vodIndex > 0)
        return LanercCommunity.barrages(json("app/chat/barragev2", linkedMapOf("vid" to JsonPrimitive(vid), "vod" to JsonPrimitive(vodIndex.toString()))))
    }

    suspend fun comments(vid: String, page: Int = 1): LanercCommentPage {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(vid) && page > 0)
        return LanercCommunity.comments(json("app/chat/comment", linkedMapOf("vid" to JsonPrimitive(vid), "page" to JsonPrimitive(page.toString()))))
    }

    suspend fun captcha(): LanercCaptcha {
        val base = backend()
        val data = LanercCatalog.payload(jsonAt(base, LanercEndpoints.CAPTCHA, body = buildJsonObject {})).jsonObject
        val count = data.getValue("option_count").jsonPrimitive.int
        val lifetime = data.getValue("expires_in").jsonPrimitive.long
        require(count in 1..100 && lifetime in 1..3600) { "Invalid captcha lifetime or options" }
        return LanercCaptcha(LanercUri.origin(base), data.getValue("challenge_id").jsonPrimitive.content,
            data.getValue("image").jsonPrimitive.content, count, nowMillis() + lifetime * 1000)
    }

    suspend fun exchange(captcha: LanercCaptcha, selected: Int): LanercGuestCredential {
        val base = backend()
        require(LanercUri.origin(base) == captcha.origin && captcha.expiresAtMillis > nowMillis()) { "Captcha expired or backend changed" }
        require(captcha.challengeId.isNotBlank() && selected in 0..captcha.optionCount) { "Invalid captcha selection" }
        // APK 0x930984/0x93099c: challenge_id, selected. Selected is converted to String at 0x9309e4.
        val body = buildJsonObject { put("challenge_id", captcha.challengeId); put("selected", selected.toString()) }
        val data = LanercCatalog.payload(jsonAt(base, LanercEndpoints.GUEST_CREDENTIAL, body = body)).jsonObject
        val value = data.getValue("guest_credential").jsonPrimitive.content
        val lifetime = data.getValue("expires_in").jsonPrimitive.long
        require(value.isNotBlank() && lifetime in 1..604800) { "Invalid guest credential response" }
        return LanercGuestCredential(captcha.origin, value, nowMillis() + lifetime * 1000)
    }

    suspend fun play(resourceId: String, credential: LanercGuestCredential): LanercPlayResult {
        val base = backend()
        require(resourceId.isNotBlank()) { "Resource ID is required" }
        require(credential.origin == LanercUri.origin(base) && credential.expiresAtMillis > nowMillis()) { "Guest credential expired or belongs to another backend" }
        val body = buildJsonObject { put("resource_id", resourceId); put("guest_credential", credential.value) }
        return protocol.decodePlayResponse(request(base, LanercEndpoints.GUEST_PLAY, emptyMap(), body, true))
    }
}
