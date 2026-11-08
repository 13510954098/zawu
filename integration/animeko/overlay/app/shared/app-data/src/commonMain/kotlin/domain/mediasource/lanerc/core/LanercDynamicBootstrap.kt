// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import io.ktor.http.Url
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.*

/** Runtime plan, not a claim about an original exported-source file schema. */
class LanercBootstrapPlan(
    val sourceId: String,
    domains: List<String>,
    providers: List<String>,
) {
    val domains = domains.toList()
    val providers = providers.toList()
    init {
        require(sourceId.isNotBlank() && sourceId.length <= 128)
        require(domains.size in 1..8 && providers.size in 1..4)
        require(domains.all { Regex("[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?").matches(it) && ".." !in it })
        require(providers.all { url -> publicHttpsUrl(url) && Url(url).parameters.isEmpty() })
    }
    companion object {
        /** Built in as a dynamic discovery plan, not a pinned media/backend URL. */
        fun builtIn() = LanercBootstrapPlan(
            "lanerc-builtin",
            listOf("dohx.lanerc.moe", "doh.lanercdns1.cc", "doh.uminadns2.cc"),
            listOf("https://dns.google/resolve", "https://doh.pub/resolve", "https://dns.alidns.com/resolve"),
        )
    }
}

class ResolvedLanercBackend(val baseUrl: String, val expiresAtMillis: Long) {
    override fun toString() = "ResolvedLanercBackend(baseUrl=REDACTED, expiresAtMillis=$expiresAtMillis)"
}

/**
 * Fetches public TXT only through an injected transport; does not call protected APIs.
 * Each instance is bound to one source plan. Cache is bounded by DNS TTL, never shared across sources.
 * ECB decoding does not authenticate DNS or the backend. Credential stores must bind to origin.
 */
class LanercDynamicBootstrap(
    private val plan: LanercBootstrapPlan,
    private val protocol: LanercProtocol,
    private val nowMillis: () -> Long,
    private val fetchPublicJson: suspend (String) -> String,
    private val requestTimeoutMillis: Long = 4_000,
) {
    private val mutex = Mutex()
    private var cached: ResolvedLanercBackend? = null
    init { require(requestTimeoutMillis in 1..30_000) }

    suspend fun invalidate() = mutex.withLock { cached = null }

    suspend fun resolve(): ResolvedLanercBackend = mutex.withLock {
        cached?.takeIf { it.expiresAtMillis > nowMillis() }?.let { return@withLock it }
        for (domain in plan.domains) for (provider in plan.providers) {
            try {
                val raw = withTimeoutOrNull(requestTimeoutMillis) { fetchPublicJson("$provider?name=$domain&type=TXT") } ?: continue
                require(raw.length <= 128 * 1024) { "DNS response size limit" }
                val response = Json.parseToJsonElement(raw).jsonObject
                if (response["Status"]?.jsonPrimitive?.intOrNull != 0) continue
                val answers = response["Answer"]?.jsonArray ?: continue
                for (value in answers) {
                  try {
                    val answer = value.jsonObject
                    if (answer["type"]?.jsonPrimitive?.intOrNull != 16) continue
                    if (answer["name"]?.jsonPrimitive?.content?.trimEnd('.')?.equals(domain, ignoreCase = true) != true) continue
                    val encoded = txtChunks(answer.getValue("data").jsonPrimitive.content)
                    if (encoded.length > 4096) continue
                    val url = protocol.decodeBootstrapTxt(encoded)
                    if (!publicHttpsUrl(url)) continue
                    val ttlMillis = (answer["TTL"]?.jsonPrimitive?.longOrNull ?: 0).coerceIn(0, 300) * 1000
                    val result = ResolvedLanercBackend(url, nowMillis() + ttlMillis)
                    cached = result
                    return@withLock result
                  } catch (cancelled: CancellationException) {
                    throw cancelled
                  } catch (_: Exception) {
                    // A malformed TXT must not hide later valid records.
                  }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Try the next public provider without exporting payloads or decoder exceptions.
            }
        }
        throw IllegalStateException("Lanerc dynamic discovery failed; no demo or stale backend was substituted")
    }

    private fun txtChunks(raw: String): String {
        if (!raw.startsWith('"')) return raw
        val chunks = Regex("\"(?:\\\\.|[^\"\\\\])*\"").findAll(raw).toList()
        require(chunks.isNotEmpty())
        require(raw.replace(Regex("\"(?:\\\\.|[^\"\\\\])*\""), "").isBlank())
        return chunks.joinToString("") { Json.decodeFromString<String>(it.value) }
    }
}

/** Media CDN URLs may be HTTP; API/backend URLs remain HTTPS-only. No auth headers are forwarded. */
internal fun publicMediaUrl(value: String): Boolean = when {
    value.startsWith("https://") -> publicHttpsUrl(value)
    value.startsWith("http://") -> publicHttpsUrl("https://" + value.removePrefix("http://"))
    else -> false
}

/** Reject control characters, embedded credentials, literal private endpoints and malformed ports. */
internal fun publicHttpsUrl(value: String): Boolean = try {
    val url = Url(value)
    val host = url.host.lowercase().trimEnd('.')
    url.protocol.name == "https" && value.startsWith("https://") &&
        value.none { it.isWhitespace() || it.code < 32 || it.code == 127 || it == '\\' } &&
        url.user == null && url.password == null && url.fragment.isEmpty() &&
        url.port in 1..65535 && host.contains('.') &&
        host.substringAfterLast('.').let { it.length >= 2 && it.all { char -> char in 'a'..'z' } } &&
        host.none { it == ':' || it == '%' } &&
        !Regex("[0-9.]+").matches(host) &&
        host != "localhost" && !host.endsWith(".localhost") && !host.endsWith(".local") && !host.endsWith(".internal")
} catch (_: Exception) { false }
