// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

/** Native response schemas, but every identifier, string and content value is synthetic/redacted. */
class LanercObservedSchemaTest {
    private val fixtures = Json.parseToJsonElement(File(System.getProperty("lanerc.native.fixtures")).readText())
        .jsonObject.getValue("fixtures").jsonObject

    @Test fun `observed 201 search and v2 detail preserve native lines and resources`() {
        val subjects = LanercCatalog.search(fixtures.getValue("search"))
        assertEquals(2, subjects.size)
        assertEquals("1", subjects.first().id)
        val lines = LanercCatalog.lines(fixtures.getValue("detail"))
        assertEquals(4, lines.size)
        assertEquals("line1", lines.first().id)
        assertTrue(lines.first().episodes.first().id.length > 128)
        assertTrue(lines.first().episodes.first().id.endsWith("_1_1"))
        assertEquals("第1集", lines.first().episodes.first().title)
        assertEquals("app/v2/vod/", LanercEndpoints.DETAIL_PREFIX)
    }

    @Test fun `observed comment parent cid and reply id shapes decode with extra native fields`() {
        val page = LanercCommunity.comments(fixtures.getValue("comments"))
        assertEquals(2, page.comments.size)
        assertTrue(page.comments.first().replies.isNotEmpty())
        assertEquals("fixture", page.comments.first().nickname)
        assertEquals("1", page.comments.first().replies.first().id)
    }

    @Test fun `observed old and new barrage schemas support ARGB top and scrolling`() {
        val rows = LanercCommunity.barrages(fixtures.getValue("barrages"))
        assertEquals(4, rows.size)
        val rendered = rows.mapNotNull(LanercCommunity::render)
        assertEquals(4, rendered.size)
        assertEquals(2, rendered.count { it.top })
        assertTrue(rendered.all { it.rgb == 0xffffff })
        assertEquals(1000L, rendered.first().timeMillis)
    }
}
