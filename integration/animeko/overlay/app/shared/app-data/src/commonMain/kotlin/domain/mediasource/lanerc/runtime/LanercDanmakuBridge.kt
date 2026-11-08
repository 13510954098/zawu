// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercBarrage
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCommunity
import me.him188.ani.danmaku.api.*
import me.him188.ani.danmaku.api.provider.*
import me.him188.ani.datasources.api.Media

/** Source-local results, never persisted into Bangumi's subject/episode danmaku cache. */
fun Flow<Media?>.lanercDanmakuResults(
    read: suspend (Media) -> List<LanercBarrage>,
): Flow<List<DanmakuFetchResult>> = flatMapLatest { media ->
    flow {
        // Clear the old source/episode immediately, before any network or credential lookup.
        emit(emptyList())
        if (media == null) return@flow
        try {
            val service = DanmakuServiceId("Lanerc · ${media.mediaSourceId}")
            val rows = read(media).mapNotNull(LanercCommunity::render)
                .distinctBy { Triple(it.id, it.timeMillis, it.content) }
            val list = rows.map { row ->
                DanmakuInfo(
                    id = "${media.mediaSourceId}.${media.mediaId}.${row.id}.${row.timeMillis}",
                    serviceId = service,
                    senderId = "", // Native read DTO does not identify the sender; never impersonate an Animeko account.
                    content = DanmakuContent(row.timeMillis, row.rgb, row.content,
                        if (row.top) DanmakuLocation.TOP else DanmakuLocation.NORMAL),
                )
            }
            emit(listOf(DanmakuFetchResult(
                DanmakuProviderId("lanerc-native:${media.mediaSourceId}"),
                DanmakuMatchInfo(service, list.size, DanmakuMatchMethod.Exact(
                    media.properties.subjectName ?: media.originalTitle,
                    media.properties.episodeName ?: media.originalTitle,
                )), list,
            )))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) {
            // No sensitive backend exception is exposed; the independent native list offers retry/error UI.
            emit(emptyList())
        }
    }
}
