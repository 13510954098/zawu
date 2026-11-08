// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import me.him188.ani.app.domain.mediasource.lanerc.core.*
import me.him188.ani.app.ui.framework.runAniComposeUiTest
import me.him188.ani.datasources.api.*
import me.him188.ani.datasources.api.source.*
import me.him188.ani.datasources.api.topic.*
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent
import me.him188.ani.app.domain.mediasource.lanerc.runtime.lanercDanmakuResults
import me.him188.ani.danmaku.api.DanmakuLocation
import kotlin.test.assertTrue
import kotlin.test.Test
import kotlin.test.assertEquals

/** Synthetic UI tests only: no native account, production server or real video. */
class LanercCommentSectionTest {
    @Test fun sourceNoticeDoesNotAppearWithoutSelectedNativeMedia() = runAniComposeUiTest {
        setContent { MaterialTheme { LanercSourceNotice(null) } }
        onNodeWithTag("lanerc.source.notice").assertDoesNotExist()
    }

    @Test fun sourceNoticeFollowsSelectionWithoutClaimingPlayback() = runAniComposeUiTest {
        val selected = mutableStateOf<Media?>(media("resource1"))
        setContent { MaterialTheme { LanercSourceNotice(selected.value) } }
        onNodeWithText("资源来源：Lanerc").assertExists()
        onNodeWithText("已选择 Lanerc 资源；不代表已解析或开始播放。").assertExists()
        runOnIdle { selected.value = null }
        onNodeWithTag("lanerc.source.notice").assertDoesNotExist()
        runOnIdle { selected.value = media("resource2") }
        onNodeWithText("资源来源：Lanerc").assertExists()
    }

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
    @Test fun nativePostingRequiresExplicitConfirmationAndCancelDoesNotPublish() = runAniComposeUiTest {
        var posts = 0
        setContent { MaterialTheme { NativeWriteComposer("fixture destination", 500, { text ->
            assertEquals("fixture-publication", text); posts++
        }, {}) } }
        onNodeWithTag("lanerc.write.input").performTextInput("fixture-publication")
        runOnIdle { assertEquals(0, posts) }
        onNodeWithTag("lanerc.write.open").performClick()
        runOnIdle { assertEquals(0, posts) }
        onNodeWithText("取消").performClick()
        runOnIdle { assertEquals(0, posts) }
        onNodeWithTag("lanerc.write.open").performClick()
        onNodeWithTag("lanerc.write.confirm").performClick()
        waitForIdle()
        runOnIdle { assertEquals(1, posts) }
        onNodeWithText("服务器已确认接收。").assertExists()
    }
    @Test fun failedNativePublicationIsNotAutomaticallyRetriedOrReportedAsSuccess() = runAniComposeUiTest {
        var posts = 0
        setContent { MaterialTheme { NativeWriteComposer("fixture destination", 500, { posts++; error("fixture failure") }, {}) } }
        onNodeWithTag("lanerc.write.input").performTextInput("fixture draft")
        onNodeWithTag("lanerc.write.open").performClick()
        onNodeWithTag("lanerc.write.confirm").performClick()
        waitForIdle()
        runOnIdle { assertEquals(1, posts) }
        onNodeWithText("服务器已确认接收。").assertDoesNotExist()
    }

    @Test fun nativeTimelineMapsTopScrollTimeAndDeduplicatesWithoutChangingOriginalServices() = runTest {
        val emissions = flowOf<Media?>(media("resource1")).lanercDanmakuResults {
            listOf(LanercBarrage("a", "#ffff0000", 1, 1.25, "top"),
                LanercBarrage("a", "#ffff0000", 1, 1.25, "top"),
                LanercBarrage("b", "#ffffffff", 5, 2.0, "scroll"))
        }.toList()
        assertTrue(emissions.first().isEmpty())
        val result = emissions.last().single()
        assertEquals(2, result.list.size)
        assertEquals(DanmakuLocation.TOP, result.list.first().location)
        assertEquals(DanmakuLocation.NORMAL, result.list.last().location)
        assertEquals(1250L, result.list.first().playTimeMillis)
        assertEquals("Lanerc · native-source", result.matchInfo.serviceId.value)
        assertEquals("", result.list.first().senderId)
    }

    @Test fun nativeTimelineClearsWhenSelectionIsNotNative() = runTest {
        var calls = 0
        val emissions = flowOf<Media?>(null).lanercDanmakuResults { calls++; error("Unexpected native request") }.toList()
        assertEquals(0, calls)
        assertTrue(emissions.all { it.isEmpty() })
    }

    @Test fun switchingMediaCancelsOldNativeRequestAndCannotPublishItsRows() = runTest {
        val selected = MutableStateFlow<Media?>(media("old"))
        var cancelled = false
        val emittedIds = mutableListOf<String>()
        backgroundScope.launch {
            selected.lanercDanmakuResults {
                if (it.mediaId == "old") {
                    try { awaitCancellation() } finally { cancelled = true }
                }
                listOf(LanercBarrage("new-row", "#ffffffff", 0, 1.0, "new-episode"))
            }.collect { results -> emittedIds.addAll(results.flatMap { it.list }.map { it.id }) }
        }
        runCurrent()
        selected.value = media("new")
        runCurrent()
        assertTrue(cancelled)
        assertTrue(emittedIds.isNotEmpty())
        assertTrue(emittedIds.all { ".new." in it && ".old." !in it })
    }

}
