// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.settings.tabs.media.source

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import me.him188.ani.app.domain.mediasource.lanerc.core.LanercUri
import me.him188.ani.app.domain.mediasource.lanerc.runtime.LanercMediaSource

/** Native account only; no automatic registration or sharing Animeko/Bangumi credentials. */
@Composable
internal fun LanercAccountControls(source: LanercMediaSource, enabled: Boolean, onBusyChange: (Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var origin by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") } // Not rememberSaveable; never persisted.
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    fun updateBusy(value: Boolean) { busy = value; onBusyChange(value) }
    Column {
        Text("原版账号（独立于访客播放凭据）", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(enabled = enabled && !busy, onClick = {
                updateBusy(true)
                scope.launch {
                    try { origin = LanercUri.origin(source.session.api().backend()) }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { status = "无法确认登录后端，请检查此源配置。" }
                    finally { updateBusy(false) }
                }
            }) { Text("登录 Lanerc 原版账号") }
            TextButton(enabled = enabled && !busy, onClick = {
                updateBusy(true)
                scope.launch {
                    try { source.logoutAccount(); status = "此源的原版账号令牌已从本机删除；未修改其他源或访客凭据。" }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { status = "本机退出未完成，请重试。" }
                    finally { updateBusy(false) }
                }
            }) { Text("退出此源账号") }
        }
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
    }
    val confirmed = origin
    if (confirmed != null) AlertDialog(
        onDismissRequest = { if (!busy) { origin = null; username = ""; password = "" } },
        title = { Text("登录 Lanerc 原版账号") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("仅向已确认的后端发送：$confirmed")
                Text("只使用你自己的原版账号。密码不保存；返回的令牌按源和后端用 Android KeyStore 加密保护。不会创建账号或使用 Animeko 登录。")
                OutlinedTextField(username, { if (it.length <= 320) username = it }, enabled = !busy, label = { Text("原版账号") }, singleLine = true)
                OutlinedTextField(password, { if (it.length <= 4096) password = it }, enabled = !busy, label = { Text("原版密码") }, singleLine = true, visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = { origin = null; username = ""; password = "" }) { Text("取消") } },
        confirmButton = { TextButton(enabled = !busy && username.isNotBlank() && password.isNotEmpty(), onClick = {
            val account = username
            val secret = password
            username = ""; password = ""; updateBusy(true)
            scope.launch {
                try {
                    source.loginAccount(account, secret, confirmed)
                    origin = null
                    status = "原版账号令牌已在本机隔离保存；服务器可随时撤销令牌。"
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { origin = null; status = "登录未完成：请检查原版账号、服务状态及后端是否变化。" }
                finally { updateBusy(false) }
            }
        }) { Text("确认登录此后端") } },
    )
}
