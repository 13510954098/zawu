// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** Every native publication requires explicit confirmation. Never auto-retry a POST. */
@Composable
internal fun NativeWriteComposer(
    destination: String,
    limit: Int,
    onSend: suspend (String) -> Unit,
    onSuccess: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    Column {
        OutlinedTextField(text, { if (it.length <= limit) text = it }, enabled = !busy,
            label = { Text(destination) }, maxLines = 3, modifier = Modifier.fillMaxWidth().testTag("lanerc.write.input"))
        TextButton(enabled = !busy && text.isNotBlank(), modifier = Modifier.testTag("lanerc.write.open"), onClick = { confirm = text }) { Text("发送到 Lanerc…") }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
    }
    confirm?.let { draft ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("确认发送到 $destination？") },
            text = { Text("$draft\n\n使用此源的原版账号发布，不会发送到 Animeko/Bangumi。请先在源设置中登录。") },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("取消") } },
            confirmButton = { TextButton(modifier = Modifier.testTag("lanerc.write.confirm"), onClick = {
                confirm = null; busy = true; status = ""
                scope.launch {
                    try { onSend(draft); text = ""; status = "服务器已确认接收。"; onSuccess() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { status = "未确认发送结果：请检查此源登录和服务状态，并先刷新列表确认，避免重复发送。不会自动重试。" }
                    finally { busy = false }
                }
            }) { Text("确认发布") } },
        )
    }
}
