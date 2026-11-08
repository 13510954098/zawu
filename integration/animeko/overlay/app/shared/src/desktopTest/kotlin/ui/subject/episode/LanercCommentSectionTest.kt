// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import me.him188.ani.app.domain.mediasource.lanerc.core.*
import me.him188.ani.app.ui.framework.runAniComposeUiTest
import me.him188.ani.datasources.api.*
import me.him188.ani.datasources.api.source.*
import me.him188.ani.datasources.api.topic.*
import kotlin.test.Test
import kotlin.test.assertEquals

/** Synthetic UI tests only: no native account, production server or real video. */
class LanercCommentSectionTest {
    private fun media(id: String) = DefaultMedia(
        mediaId = id, mediaSourceId = "native-source", originalTitle = id, publishedTime = 0L,
        originalUrl = "https://lanerc.invalid/resource/$id?vod_index=1",
        download = ResourceLocation.WebVideo("https://lanerc.invalid/resource/$id?vod_index=1", apiParameters = mapOf("resource_id" to id, "vod_id" to "native-vod", "vod_index" to "1")),
        properties = MediaProperties(subjectName = "Fixture", episodeName = id, subtitleLanguageIds = emptyList(), resolution = "", alliance = "", size = FileSize.Unspecified, subtitleKind = null),
        episodeRange = null, location = MediaSourceLocation.Online, kind = MediaSourceKind.WEB,
    )

    @Test fun nonNativeMediaPreservesAnimekoWithoutRequests() = runAniComposeUiTest {
        var requests = 0
        setContent {
            MaterialTheme {
                LanercCommentSection(null, { _, _ -> requests++; error("Unexpected native request") }, { requests++; error("Unexpected native request") }) {
                    Text("original-comments")
                }
            }
        }
        onNodeWithText("original-comments").assertExists()
        onNodeWithTag("lanerc.comments.native").assertDoesNotExist()
        runOnIdle { assertEquals(0, requests) }
    }

    @Test fun nativeCommentsLoadOnlyAfterSelectionAndResetForNewMedia() = runAniComposeUiTest {
        val selected = mutableStateOf<Media?>(media("resource1"))
        var requests = 0
        setContent {
            MaterialTheme {
                LanercCommentSection(selected.value, { item, page ->
                    requests++
                    assertEquals("resource1", item.mediaId)
                    assertEquals(1, page)
                    LanercCommentPage(1, listOf(LanercComment("id", "date", "native-user", "<b>native-plain-text</b>", emptyList())))
                }, { error("Barrage tab was not selected") }) { Text("original-comments") }
            }
        }
        onNodeWithText("original-comments").assertExists()
        runOnIdle { assertEquals(0, requests) }
        onNodeWithTag("lanerc.comments.native").performClick()
        waitForIdle()
        onNodeWithText("<b>native-plain-text</b>").assertExists()
        runOnIdle { assertEquals(1, requests); selected.value = media("resource2") }
        waitForIdle()
        onNodeWithText("original-comments").assertExists()
        onNodeWithText("<b>native-plain-text</b>").assertDoesNotExist()
        runOnIdle { assertEquals(1, requests) }
    }

    @Test fun nativeBarrageTabUsesIndependentLoaderAndShowsPlainContent() = runAniComposeUiTest {
        var comments = 0
        var barrages = 0
        setContent {
            MaterialTheme {
                LanercCommentSection(media("resource1"), { _, _ -> comments++; error("Unexpected comments request") }, {
                    barrages++
                    listOf(LanercBarrage("id", "#ffffff", 9, 65.0, "native-barrage-text"))
                }) { Text("original-comments") }
            }
        }
        onNodeWithTag("lanerc.barrages.native").performClick()
        waitForIdle()
        onNodeWithText("native-barrage-text").assertExists()
        onNodeWithText("1:05 · 位置 9 · #ffffff").assertExists()
        runOnIdle { assertEquals(0, comments); assertEquals(1, barrages) }
        onNodeWithTag("lanerc.comments.animeko").performClick()
        onNodeWithText("original-comments").assertExists()
    }
}
