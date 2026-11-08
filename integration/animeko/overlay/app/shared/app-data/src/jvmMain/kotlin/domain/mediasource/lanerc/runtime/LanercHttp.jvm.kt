// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.engine.okhttp.OkHttpConfig
import okhttp3.Authenticator

/** Ktor's no-retry plugin policy alone does not disable OkHttp's automatic POST recovery. */
internal fun HttpClientConfig<*>.hardenLanercJvmClient() {
    @Suppress("UNCHECKED_CAST")
    (this as HttpClientConfig<HttpClientEngineConfig>).engine {
        check(this is OkHttpConfig) { "Unexpected native source HTTP engine" }
        config {
            retryOnConnectionFailure(false)
            followRedirects(false)
            followSslRedirects(false)
            authenticator(Authenticator.NONE)
            proxyAuthenticator(Authenticator.NONE)
        }
    }
}
