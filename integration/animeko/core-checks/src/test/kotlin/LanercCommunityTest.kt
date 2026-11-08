// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic, statically anchored DTO fixtures; these are NOT captured production responses. */
class LanercCommunityTest {
    private val key = ByteArray(32) { it.toByte() }
    private val protocol = LanercProtocol(LanercJvmCrypto(), LanercSecrets("fixture-suffix-17", key, key, key, emptyList()))
    private val comments = """{"vod_comment":{"total":2,"comment":[{"cid":19,"created_at":"2026-11-08","nick_name":"用户","content":"<b>纯文本</b>","replies":[{"id":20,"created_at":"2026-11-08","nick_name":"回复者","content":"回复"}]}]}}"""
    private val barrage = """{"new_barrages":[{"id":1,"bcolor":"#ffffff","position":2,"second":1.25,"content":"新弹幕"}],"old_barrages":[{"id":2,"bcolor":"16711680","position":9,"second":2,"content":"旧弹幕"}]}"""

    @Test fun `native comment field and distinct reply id are preserved without interpreting HTML`() {
        val page = LanercCommunity.comments(Json.parseToJsonElement(comments))
        assertEquals(2, page.total)
        assertEquals("19", page.comments.single().id)
        assertEquals("<b>纯文本</b>", page.comments.single().content)
        assertEquals("20", page.comments.single().replies.single().id)
        assertEquals("回复者", page.comments.single().replies.single().nickname)
    }

    @Test fun `both barrage generations retain native position and fractional seconds`() {
        val result = LanercCommunity.barrages(Json.parseToJsonElement(barrage))
        assertEquals(listOf("新弹幕", "旧弹幕"), result.map { it.content })
        assertEquals(1.25, result.first().second)
        assertEquals(9, result.last().position)
        assertEquals("16711680", result.last().color)
    }

    @Test fun `invalid barrage times and malformed community records are rejected`() {
        assertFails { LanercCommunity.barrages(Json.parseToJsonElement(barrage.replace("1.25", "-1"))) }
        assertFails { LanercCommunity.comments(Json.parseToJsonElement(comments.replace("\"comment\"", "\"list\""))) }
        assertFails { LanercCommunity.comments(Json.parseToJsonElement(comments.replace("\"total\":2", "\"total\":-1"))) }
    }

    @Test fun `JSON serialized data is decoded and native comment endpoint signs ordered parameters`() = runTest {
        var requested = ""
        val api = LanercApi(protocol, { "https://example.invalid/api/" }, { 1000 }, { "abc" }) { request ->
            requested = request.url
            buildJsonObject { put("code", 200); put("data", comments) }.toString().encodeToByteArray()
        }
        assertEquals(2, api.comments("37", 3).total)
        assertTrue(requested.startsWith("https://example.invalid/api/app/chat/comment?vid=37&page=3&sign="))
        assertFalse(requested.contains("guest_credential"))
    }

    @Test fun `barrage vod parameter is native one based list position not resource id`() = runTest {
        var requested = ""
        val api = LanercApi(protocol, { "https://example.invalid/" }, { 1000 }, { "abc" }) { request ->
            requested = request.url
            barrage.encodeToByteArray()
        }
        assertEquals(2, api.barrages("37", 4).size)
        assertTrue(requested.contains("barragev2?vid=37&vod=4&sign="))
        assertFails { api.barrages("37", 0) }
        assertFails { api.comments("37&other=1") }
    }

    @Test fun `native playlist uses resource_id and preserves player and display name separately`() {
        val lines = LanercCatalog.lines(Json.parseToJsonElement("""{"video_play_list":[{"player":"line1","name":"线路一","video":[{"resource_id":"r12","title":"第2集"}]}]}"""))
        assertEquals("line1", lines.single().id)
        assertEquals("线路一", lines.single().name)
        assertEquals("r12", lines.single().episodes.single().id)
        assertFails { LanercCatalog.lines(Json.parseToJsonElement("""{"video_play_list":[{"player":"line1","name":"线路一","video":[{"id":"r12","title":"第2集"}]}]}""")) }
    }
}
