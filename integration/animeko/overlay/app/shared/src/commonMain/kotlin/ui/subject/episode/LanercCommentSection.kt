// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercComment
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercCommentPage
import me.him188.ani.datasources.api.Media

/** Independent read-only native comments; never substitutes native IDs or authentication for Bangumi. */
@Composable
internal fun LanercCommentSection(
    media: Media?,
    load: suspend (Media, Int) -> LanercCommentPage,
    animekoContent: @Composable () -> Unit,
) {
    var native by remember(media?.mediaId) { mutableStateOf(false) }
    if (media == null) {
        animekoContent()
        return
    }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(!native, { native = false }, label = { Text("Animeko 评论") }, modifier = Modifier.testTag("lanerc.comments.animeko"))
            FilterChip(native, { native = true }, label = { Text("Lanerc 作品评论") }, modifier = Modifier.testTag("lanerc.comments.native"))
        }
        if (!native) Box(Modifier.weight(1f)) { animekoContent() }
        else NativeCommentList(media, load, Modifier.weight(1f))
    }
}

@Composable
private fun NativeCommentList(media: Media, load: suspend (Media, Int) -> LanercCommentPage, modifier: Modifier) {
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
        Text("当前只读；原版用户登录与发送尚未接入。", style = MaterialTheme.typography.bodySmall)
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
                items(current.comments) { comment -> NativeComment(comment) }
            }
        } else Spacer(Modifier.weight(1f))
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
