// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** JVM APIs available on Android API 24+ and desktop; not an iOS implementation. */
class LanercJvmCrypto : LanercCrypto {
    override fun md5(input: ByteArray): String = MessageDigest.getInstance("MD5").digest(input)
        .joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }

    override fun decryptGcm(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12 && ciphertextAndTag.size >= 16) { "Invalid GCM input" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertextAndTag)
    }

    override fun decryptEcbPkcs7(key: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.size == 32 && ciphertext.isNotEmpty() && ciphertext.size % 16 == 0) { "Invalid ECB input" }
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding") // JCE name; AES uses PKCS7 block padding.
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(ciphertext)
    }
}
