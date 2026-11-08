// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercBarrage
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercComment
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCommentPage
import me.him188.ani.datasources.api.Media

/** Independent read-only native comments; never substitutes native IDs or authentication for Bangumi. */
@Composable
internal fun LanercCommentSection(
    media: Media?,
    load: suspend (Media, Int) -> LanercCommentPage,
    loadBarrages: suspend (Media) -> List<LanercBarrage>,
    sendComment: (suspend (Media, String, Long) -> Unit)? = null,
    sendBarrage: (suspend (Media, String, Boolean) -> Unit)? = null,
    animekoContent: @Composable () -> Unit,
) {
    var selectedTab by remember(media?.mediaId) { mutableStateOf(0) }
    if (media == null) {
        animekoContent()
        return
    }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selectedTab == 0, { selectedTab = 0 }, label = { Text("Animeko 评论") }, modifier = Modifier.testTag("lanerc.comments.animeko"))
            FilterChip(selectedTab == 1, { selectedTab = 1 }, label = { Text("Lanerc 作品评论") }, modifier = Modifier.testTag("lanerc.comments.native"))
            FilterChip(selectedTab == 2, { selectedTab = 2 }, label = { Text("Lanerc 本集弹幕") }, modifier = Modifier.testTag("lanerc.barrages.native"))
        }
        when (selectedTab) {
            0 -> Box(Modifier.weight(1f)) { animekoContent() }
            1 -> NativeCommentList(media, load, Modifier.weight(1f), sendComment)
            2 -> NativeBarrageList(media, loadBarrages, Modifier.weight(1f), sendBarrage)
        }
    }
}

@Composable
private fun NativeCommentList(media: Media, load: suspend (Media, Int) -> LanercCommentPage, modifier: Modifier, send: (suspend (Media, String, Long) -> Unit)?) {
    var replyId by remember(media.mediaId) { mutableStateOf(0L) }
    var page by remember(media.mediaId) { mutableStateOf(1) }
    var retry by remember(media.mediaId) { mutableStateOf(0) }
    var result by remember(media.mediaId) { mutableStateOf<LanercCommentPage?>(null) }
    var loading by remember(media.mediaId) { mutableStateOf(false) }
    var failed by remember(media.mediaId) { mutableStateOf(false) }
    LaunchedEffect(media.mediaId, page, retry) {
        result = null // Never display a previous page while loading a new episode/source/page.
        failed = false
        loading = true
        try { result = load(media, page) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { failed = true } // Backend errors may contain sensitive URLs: do not render them.
        finally { loading = false }
    }
    Column(modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Text("Lanerc 原版作品级评论（不是 Bangumi 单集评论）", style = MaterialTheme.typography.labelMedium)
        Text("发送需要此源的原版账号，不使用访客或 Animeko 登录。", style = MaterialTheme.typography.bodySmall)
        if (loading) LinearProgressIndicator(Modifier.fillMaxWidth().testTag("lanerc.comments.loading"))
        if (failed) {
            Text("读取失败：请检查 Lanerc 源配置、网络及服务可用性。", modifier = Modifier.testTag("lanerc.comments.error"))
            TextButton(onClick = { retry++ }) { Text("重试") }
        }
        val current = result
        if (current != null) {
            Text("共 ${current.total} 条 · 第 $page 页", style = MaterialTheme.typography.labelMedium)
            LazyColumn(Modifier.weight(1f).testTag("lanerc.comments.list"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (current.comments.isEmpty()) item { Text("本页暂无评论") }
                // Index identity avoids collisions in untrusted or repeated native comment IDs.
                items(current.comments) { comment ->
                    NativeComment(comment)
                    val id = comment.id.toLongOrNull()
                    if (send != null && id != null && id > 0) TextButton(onClick = { replyId = id }) { Text("回复此评论") }
                }
            }
        } else Spacer(Modifier.weight(1f))
        if (send != null) {
            if (replyId != 0L) TextButton(onClick = { replyId = 0L }) { Text("取消回复，改为作品评论") }
            NativeWriteComposer("Lanerc ${if (replyId == 0L) "作品评论" else "评论回复"}", 4096,
                onSend = { text -> send(media, text, replyId) }, onSuccess = { retry++; replyId = 0L })
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TextButton(onClick = { page-- }, enabled = !loading && page > 1) { Text("上一页") }
            TextButton(onClick = { page++ }, enabled = !loading && !current?.comments.isNullOrEmpty() && page < 10000) { Text("下一页") }
        }
    }
}

@Composable
private fun NativeComment(comment: LanercComment) {
    Column {
        Text(comment.nickname.take(120), style = MaterialTheme.typography.titleSmall)
        Text(comment.createdAt.take(80), style = MaterialTheme.typography.labelSmall)
        // Plain Compose Text: native HTML, links and scripts are not executed or loaded.
        Text(comment.content.take(12000))
        comment.replies.take(30).forEach { reply ->
            Text("${reply.nickname.take(120)}：${reply.content.take(3000)}", modifier = Modifier.padding(start = 16.dp), style = MaterialTheme.typography.bodySmall)
        }
        HorizontalDivider()
    }
}


/** Read-only list until native renderer location mapping has independent evidence. */
@Composable
private fun NativeBarrageList(media: Media, load: suspend (Media) -> List<LanercBarrage>, modifier: Modifier, send: (suspend (Media, String, Boolean) -> Unit)?) {
    var result by remember(media.mediaId) { mutableStateOf<List<LanercBarrage>?>(null) }
    var failed by remember(media.mediaId) { mutableStateOf(false) }
    var retry by remember(media.mediaId) { mutableStateOf(0) }
    LaunchedEffect(media.mediaId, retry) {
        result = null
        failed = false
        try { result = load(media).sortedBy { it.second } }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { failed = true }
    }
    Column(modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Text("Lanerc 本集弹幕 · 只读列表", style = MaterialTheme.typography.titleSmall)
        Text("使用原版作品 ID 和线路内选集序号；发送需要在设置中登录此源的原版账号。", style = MaterialTheme.typography.bodySmall)
        var top by remember(media.mediaId) { mutableStateOf(false) }
        if (send != null) {
            FilterChip(top, { top = !top }, label = { Text(if (top) "顶部弹幕" else "滚动弹幕") })
            NativeWriteComposer("Lanerc 当前播放位置的弹幕", 500,
                onSend = { text -> send(media, text, top) }, onSuccess = { retry++ })
        }
        when {
            failed -> {
                Text("读取失败，请检查源配置及服务可用性。", modifier = Modifier.testTag("lanerc.barrages.error"))
                TextButton(onClick = { retry++ }) { Text("重试") }
            }
            result == null -> LinearProgressIndicator(Modifier.fillMaxWidth())
            else -> {
                val rows = result.orEmpty()
                Text("共 ${rows.size} 条", style = MaterialTheme.typography.labelMedium)
                LazyColumn(Modifier.weight(1f).testTag("lanerc.barrages.list"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (rows.isEmpty()) item { Text("本集暂无弹幕") }
                    items(rows) { row ->
                        Column {
                            val seconds = row.second.toLong()
                            Text("${seconds / 60}:${(seconds % 60).toString().padStart(2, '0')} · 位置 ${row.position} · ${row.color.take(32)}", style = MaterialTheme.typography.labelSmall)
                            Text(row.content.take(12000))
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}
