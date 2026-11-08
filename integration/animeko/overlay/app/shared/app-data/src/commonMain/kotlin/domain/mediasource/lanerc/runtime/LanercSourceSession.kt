// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.*
import io.ktor.utils.io.readRemaining
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.readByteArray
import me.him188.ani.app.domain.mediasource.lanerc.core.*
import me.him188.ani.utils.ktor.ClientProxyConfig
import me.him188.ani.utils.ktor.getPlatformKtorEngine
import me.him188.ani.utils.ktor.proxy
import me.him188.ani.utils.platform.currentTimeMillis
import kotlin.random.Random

/** Own HTTP client: no Animeko/Bangumi auth, cookie jar, request logging or redirect following. */
class LanercSourceSession(
    private val sourceId: String,
    private val arguments: LanercMediaSourceArguments,
    private val settings: LanercSettingsStore,
    proxyConfig: ClientProxyConfig? = null,
) : AutoCloseable {
    private val http = HttpClient(getPlatformKtorEngine()) {
        expectSuccess = false
        followRedirects = false
        proxy(proxyConfig)
        install(HttpTimeout) { requestTimeoutMillis = 15_000; connectTimeoutMillis = 8_000; socketTimeoutMillis = 10_000 }
    }
    private val lock = Mutex()
    private var materialVersion: String? = null
    private var cachedApi: LanercApi? = null

    private suspend fun fetch(request: LanercRequest, limit: Int): ByteArray = try {
        http.prepareRequest(request.url) {
            method = if (request.body == null) HttpMethod.Get else HttpMethod.Post
            header(HttpHeaders.Accept, if (request.protobuf) "application/x-protobuf" else "application/json")
            request.authorization?.let { header(HttpHeaders.Authorization, it) }
            request.body?.let { contentType(ContentType.Application.Json); setBody(it) }
        }.execute { response ->
            require(response.status.value in 200..299) { "Lanerc HTTP request failed" }
            val bytes = response.bodyAsChannel().readRemaining(limit.toLong() + 1).readByteArray()
            require(bytes.size <= limit) { "Lanerc response size limit" }
            bytes
        }
    } catch (cancelled: CancellationException) { throw cancelled }
    catch (_: Exception) { error("Lanerc 请求失败，请检查源、网络或服务状态") }

    suspend fun api(): LanercApi = lock.withLock {
        check(LanercPlatform.supported) { "Lanerc 模式当前支持 Android" }
        val version = settings.sealedMaterial(sourceId)
        if (version == materialVersion) cachedApi?.let { return@withLock it }
        val protocol = LanercProtocol(LanercPlatform.crypto(), settings.unsealMaterial(sourceId, version))
        val bootstrap = LanercDynamicBootstrap(
            LanercBootstrapPlan.builtIn(), protocol, { currentTimeMillis() },
            { url -> fetch(LanercRequest(url, null, false), 128 * 1024).decodeToString(throwOnInvalidSequence = true) },
        )
        LanercApi(protocol,
            resolveBackend = { arguments.backendOverride.takeIf { it.isNotBlank() } ?: bootstrap.resolve().baseUrl },
            nowMillis = { currentTimeMillis() },
            nonce = { buildString { repeat(3) { append(('a'.code + Random.nextInt(26)).toChar()) } } },
            transport = { request -> fetch(request, LanercProtocol.MAX_BYTES) },
        ).also { cachedApi = it; materialVersion = version }
    }
    override fun close() { http.close() }
}
