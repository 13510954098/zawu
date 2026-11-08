// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.io.encoding.Base64
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCrypto
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercJvmCrypto

actual object LanercPlatform {
    actual val supported = true
    private const val ALIAS = "animeko.lanerc.private.v1"
    actual fun crypto(): LanercCrypto = LanercJvmCrypto()
    @Synchronized private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    actual fun seal(scope: String, plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(scope.encodeToByteArray())
        return Base64.encode(cipher.iv + cipher.doFinal(plaintext.encodeToByteArray()))
    }
    actual fun unseal(scope: String, ciphertext: String): String {
        val raw = Base64.decode(ciphertext)
        require(raw.size >= 28)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        cipher.updateAAD(scope.encodeToByteArray())
        return cipher.doFinal(raw.copyOfRange(12, raw.size)).decodeToString(throwOnInvalidSequence = true)
    }
}
