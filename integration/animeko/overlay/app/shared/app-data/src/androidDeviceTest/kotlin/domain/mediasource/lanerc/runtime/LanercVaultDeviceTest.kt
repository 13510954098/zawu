// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Runs on Android's actual KeyStore provider; public synthetic data only. */
class LanercVaultDeviceTest {
    @Test fun androidKeyStoreRoundTripsUnicodeAndUsesFreshNonces() {
        assertTrue(LanercPlatform.supported)
        val scope = "fixture:source:android"
        val text = "public-fixture-协议材料-🙂"
        val first = LanercPlatform.seal(scope, text)
        val second = LanercPlatform.seal(scope, text)
        assertNotEquals(first, second)
        assertEquals(text, LanercPlatform.unseal(scope, first))
        assertEquals(text, LanercPlatform.unseal(scope, second))
        assertTrue(Base64.decode(first).size >= 28)
    }

    @Test fun sourceAndOriginAreAuthenticatedByAndroidKeyStore() {
        val sealed = LanercPlatform.seal("credential:source-a:https://example.invalid:443", "public-fixture-token")
        assertFails { LanercPlatform.unseal("credential:source-b:https://example.invalid:443", sealed) }
        assertFails { LanercPlatform.unseal("credential:source-a:https://other.invalid:443", sealed) }
        assertEquals("public-fixture-token", LanercPlatform.unseal("credential:source-a:https://example.invalid:443", sealed))
    }

    @Test fun tamperedOrTruncatedCiphertextsAreRejected() {
        val scope = "protocol:public-fixture-source"
        val raw = Base64.decode(LanercPlatform.seal(scope, "public-fixture-material"))
        raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
        assertFails { LanercPlatform.unseal(scope, Base64.encode(raw)) }
        assertFails { LanercPlatform.unseal(scope, Base64.encode(ByteArray(12))) }
        assertFails { LanercPlatform.unseal(scope, "not-valid-base64!") }
    }
}
