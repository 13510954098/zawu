// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import io.ktor.http.Url
import kotlinx.serialization.json.*

/** Dio-compatible subset exercised by the pinned Dart URI fixtures and native endpoint requests. */
object LanercUri {
    fun component(value: String): String = buildString {
        for (byte in value.encodeToByteArray()) {
            val n = byte.toInt() and 255
            when {
                n in 65..90 || n in 97..122 || n in 48..57 || n.toChar() in "-._~" -> append(n.toChar())
                n == 32 -> append('+')
                else -> append('%').append(n.toString(16).uppercase().padStart(2, '0'))
            }
        }
    }

    fun canonical(base: String, path: String, query: Map<String, JsonElement> = emptyMap()): String {
        require(publicHttpsUrl(base)) { "Invalid backend" }
        require(Url(base).parameters.isEmpty()) { "Backend must not contain a query" }
        require('#' !in path && path.none { it.code < 32 }) { "Invalid path" }
        val combined = if (path.startsWith("https://", ignoreCase = true)) path else base.trimEnd('/') + "/" + path.trimStart('/')
        val parsed = Url(combined)
        require(publicHttpsUrl(combined)) { "Invalid request URI" }
        require(!parsed.parameters.contains("sign") && !query.containsKey("sign")) { "Existing sign must be removed" }
        val pathOnly = combined.substringBefore('?').substringAfter("://").substringAfter('/', "")
        val segments = mutableListOf<String>()
        for (segment in pathOnly.split('/')) when (segment) {
            "", "." -> Unit
            ".." -> if (segments.isNotEmpty()) segments.removeAt(segments.lastIndex)
            else -> segments += segment
        }
        val normalizedPath = "/" + segments.joinToString("/") + if (pathOnly.endsWith('/') && segments.isNotEmpty()) "/" else ""
        val port = if (parsed.port == 443) "" else ":${parsed.port}"
        val pairs = mutableListOf<String>()
        combined.substringAfter('?', "").takeIf { it.isNotEmpty() }?.let { pairs += it }
        for ((key, value) in query) {
            val values = if (value is JsonArray) value else listOf(value)
            for (item in values) {
                require(item is JsonPrimitive) { "Nested query objects are unsupported" }
                pairs += component(key) + if (item is JsonNull) "" else "=" + component(item.content)
            }
        }
        return "https://${parsed.host.lowercase()}$port$normalizedPath" + if (pairs.isEmpty()) "" else "?${pairs.joinToString("&")}"
    }

    fun signed(canonical: String, sign: String): String = canonical + if ('?' in canonical) "&sign=${component(sign)}" else "?sign=${component(sign)}"
    fun origin(base: String): String {
        require(publicHttpsUrl(base)) { "Invalid origin" }
        return Url(base).let { "https://${it.host.lowercase()}:${it.port}" }
    }
}
