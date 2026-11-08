// SPDX-License-Identifier: AGPL-3.0-only
@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
package me.him188.ani.app.ui.settings.tabs.media.source

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.Image
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.serialization.json.*
import me.him188.ani.app.domain.media.fetch.MediaSourceManager
import me.him188.ani.app.domain.mediasource.lanerc.core.*
import me.him188.ani.app.domain.mediasource.lanerc.runtime.*
import me.him188.ani.app.ui.foundation.decodeImageBitmap
import me.him188.ani.app.ui.foundation.LocalIsPreviewing
import me.him188.ani.datasources.api.source.MediaSourceConfig
import me.him188.ani.datasources.api.source.serializeArguments
import me.him188.ani.utils.platform.Uuid
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import kotlin.io.encoding.Base64

private class LanercSettingsDependencies : KoinComponent {
    val settings: LanercSettingsStore by inject()
    val manager: MediaSourceManager by inject()
}

@Composable
internal fun LanercModeControls(mode: SourceMode, enabled: Boolean, onMode: (SourceMode) -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        for (choice in SourceMode.entries) FilterChip(
            selected = mode == choice, enabled = enabled,
            onClick = { onMode(choice) }, modifier = Modifier.testTag("lanerc_mode_${choice.name}"),
            label = { Text(when (choice) { SourceMode.ANIMEKO -> "Animeko 源"; SourceMode.LANERC -> "Lanerc 源"; SourceMode.BOTH -> "两者并行" }) },
        )
    }
}

@Composable
internal fun LanercSettingsCard() {
    if (LocalIsPreviewing.current) { Text("Lanerc 动态源"); return }
    val dependencies = remember { LanercSettingsDependencies() }
    val settings = dependencies.settings
    val manager = dependencies.manager
    val scope = rememberCoroutineScope()
    val mode by settings.mode.collectAsState(initial = SourceMode.ANIMEKO)
    val all by manager.allInstances.collectAsState(initial = emptyList())
    val sources = all.filter { it.factoryId == LanercMediaSource.FactoryId }
    var selectedId by remember { mutableStateOf(LanercMediaSource.BUILTIN_ID) }
    val selected = sources.firstOrNull { it.mediaSourceId == selectedId } ?: sources.firstOrNull()
    val source = selected?.source as? LanercMediaSource
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var dialog by remember { mutableStateOf<String?>(null) }
    var input by remember { mutableStateOf("") } // Never save private input to SavedState.
    var dropdown by remember { mutableStateOf(false) }
    var captcha by remember { mutableStateOf<LanercCaptcha?>(null) }
    var choice by remember { mutableStateOf(1) }
    var hasMaterial by remember { mutableStateOf(false) }
    LaunchedEffect(selected?.mediaSourceId, busy) {
        hasMaterial = selected?.let { settings.hasMaterial(it.mediaSourceId) } ?: false
    }
    fun perform(block: suspend () -> String) {
        if (busy) return
        busy = true
        scope.launch {
            try { message = block() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { message = "操作失败：请检查材料、源格式、网络、验证码时效或服务器状态。" }
            finally { busy = false }
        }
    }
    ElevatedCard(Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("lanerc_settings")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Lanerc 动态源", style = MaterialTheme.typography.titleMedium)
            Text("独立源与本机访客凭据；不会共享 Animeko / Bangumi 登录。模式切换保留原源的启用设置。")
            LanercModeControls(mode, !busy) { perform { settings.setMode(it); "源模式已保存；正在播放的会话保持不变，下次资源查询使用新模式。" } }
            if (sources.none { it.mediaSourceId == LanercMediaSource.BUILTIN_ID }) TextButton(enabled = !busy, onClick = {
                perform {
                    if (manager.allInstances.first().none { it.mediaSourceId == LanercMediaSource.BUILTIN_ID }) {
                        manager.addInstance(LanercMediaSource.BUILTIN_ID, LanercMediaSource.BUILTIN_ID, LanercMediaSource.FactoryId,
                            MediaSourceConfig(serializedArguments = MediaSourceConfig.serializeArguments(LanercMediaSourceArguments.serializer(), LanercMediaSourceArguments())))
                    }
                    "已添加内置动态发现源。"
                }
            }) { Text("添加内置动态源") }
            Box {
                TextButton(onClick = { dropdown = true }, enabled = !busy && sources.isNotEmpty()) { Text("当前源：${source?.arguments?.name ?: "尚未添加"}") }
                DropdownMenu(expanded = dropdown, onDismissRequest = { dropdown = false }) {
                    for (item in sources) DropdownMenuItem(text = { Text(item.source.info.displayName) }, onClick = {
                        selectedId = item.mediaSourceId; captcha = null; dropdown = false
                    })
                }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(enabled = !busy, onClick = { input = ""; dialog = "source" }) { Text("导入原版 domain 配置（子集）") }
                TextButton(enabled = !busy && selected != null && LanercPlatform.supported, onClick = { input = ""; dialog = "material" }) { Text("导入本机协议材料") }
                TextButton(enabled = !busy && source != null && hasMaterial, onClick = {
                    val active = source ?: return@TextButton
                    perform { active.session.api().backend(); "动态源发现成功；这不代表已验证播放权限。" }
                }) { Text("检查动态发现") }
            }
            Text(if (hasMaterial) "协议材料已保存在本机密钥库保护的存储中。" else "未导入协议材料。源定义不包含 AES 材料或访客凭据。")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(enabled = !busy && source != null && hasMaterial, onClick = {
                    val active = source ?: return@TextButton
                    perform { captcha = active.session.api().captcha(); choice = 1; "请人工选择图片中正确答案的序号。" }
                }) { Text("获取访客验证码") }
                TextButton(enabled = !busy && selected != null, onClick = {
                    val id = selected?.mediaSourceId ?: return@TextButton
                    dialog = "clear"; input = id
                }) { Text("清除此源私密数据") }
            }
            captcha?.let { challenge ->
                val image = remember(challenge) { runCatching {
                    require(challenge.image.length <= 2 * 1024 * 1024)
                    require(!challenge.image.startsWith("http", ignoreCase = true))
                    decodeImageBitmap(Base64.decode(challenge.image.substringAfter("base64,", challenge.image)))
                }.getOrNull() }
                if (image != null) Image(image, "访客验证码", Modifier.fillMaxWidth().height(140.dp))
                else Text("验证码图像格式尚未支持；不会自动向未知图像地址发送请求。")
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (number in 1..challenge.optionCount) FilterChip(selected = choice == number, onClick = { choice = number }, enabled = !busy,
                        label = { Text(number.toString()) })
                }
                TextButton(enabled = !busy && image != null && source != null, onClick = {
                    val active = source ?: return@TextButton
                    val id = selected?.mediaSourceId ?: return@TextButton
                    perform {
                        val credential = active.session.api().exchange(challenge, choice)
                        settings.saveCredential(id, credential)
                        captcha = null
                        "访客凭据已按源和后端隔离保存，请重试播放。"
                    }
                }) { Text("验证并保存访客凭据") }
            }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (message.isNotBlank()) Text(message, modifier = Modifier.testTag("lanerc_status"))
        }
    }
    val currentDialog = dialog
    if (currentDialog != null) AlertDialog(
        onDismissRequest = { if (!busy) { dialog = null; input = "" } },
        title = { Text(when (currentDialog) { "material" -> "导入本机协议材料"; "clear" -> "清除此源私密数据？"; else -> "导入已确认的 domain 配置子集" }) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(when (currentDialog) {
                    "material" -> "粘贴恢复的私密 JSON。仅保存在 Android 本机；不会随源导出。输入不会进入页面恢复状态。"
                    "clear" -> "将删除协议材料和此源的所有访客凭据，不删除其他源或 Animeko 账号。"
                    else -> "仅接受原版后备配置中已确认的 domain HTTPS 字段。完整原版源包格式尚未核实，不会伪称已兼容。"
                })
                if (currentDialog != "clear") OutlinedTextField(input, onValueChange = { if (it.length <= 65536) input = it }, enabled = !busy,
                    minLines = 3, maxLines = 7, modifier = Modifier.testTag("lanerc_import_input"),
                    visualTransformation = if (currentDialog == "material") PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None)
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = { dialog = null; input = "" }) { Text("取消") } },
        confirmButton = { TextButton(enabled = !busy && input.isNotBlank(), onClick = {
            val raw = input
            val activeId = selected?.mediaSourceId
            input = ""; dialog = null
            perform {
                when (currentDialog) {
                    "clear" -> { settings.clearPrivate(raw); captcha = null; "此源私密数据已清除。" }
                    "material" -> { settings.importMaterial(requireNotNull(activeId), raw); "协议材料已在本机加密保存。" }
                    else -> {
                        val parsed = Json.parseToJsonElement(raw).jsonObject
                        val backend = parsed.getValue("domain").jsonPrimitive.content
                        // The API validates HTTPS, credentials, ports and host form before any protected request.
                        LanercUri.canonical(backend, "")
                        val name = parsed["name"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }?.take(80) ?: "Lanerc 导入源"
                        val id = "lanerc.${Uuid.randomString()}"
                        val arguments = LanercMediaSourceArguments(name, backend)
                        manager.addInstance(id, id, LanercMediaSource.FactoryId, MediaSourceConfig(
                            serializedArguments = MediaSourceConfig.serializeArguments(LanercMediaSourceArguments.serializer(), arguments)))
                        selectedId = id
                        "已导入 domain 配置子集；此源需要单独导入本机协议材料。"
                    }
                }
            }
        }) { Text(if (currentDialog == "clear") "确认清除" else "导入") } },
    )
}
