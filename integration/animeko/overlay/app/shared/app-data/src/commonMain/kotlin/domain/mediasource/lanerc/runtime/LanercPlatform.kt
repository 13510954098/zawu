// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCrypto

expect object LanercPlatform {
    fun hardenHttp(config: io.ktor.client.HttpClientConfig<*>)
    val supported: Boolean
    fun crypto(): LanercCrypto
    fun seal(scope: String, plaintext: String): String
    fun unseal(scope: String, ciphertext: String): String
}
