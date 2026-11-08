// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCrypto

actual object LanercPlatform {
    actual fun hardenHttp(config: io.ktor.client.HttpClientConfig<*>) { /* Runtime unsupported on this platform. */ }
    actual val supported = false
    actual fun crypto(): LanercCrypto = error("Lanerc runtime currently requires Android")
    actual fun seal(scope: String, plaintext: String): String = error("A platform credential vault is required")
    actual fun unseal(scope: String, ciphertext: String): String = error("A platform credential vault is required")
}
