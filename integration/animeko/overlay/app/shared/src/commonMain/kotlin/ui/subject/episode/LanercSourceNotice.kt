// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.ui.subject.episode

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import me.him188.ani.datasources.api.Media

/** Selection provenance only. Neither search mode nor selection proves playback. */
@Composable
internal fun LanercSourceNotice(media: Media?) {
    if (media == null) return
    Surface(
        modifier = Modifier.fillMaxWidth().testTag("lanerc.source.notice"),
        color = MaterialTheme.colorScheme.secondaryContainer,
    ) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text("资源来源：Lanerc", style = MaterialTheme.typography.labelLarge)
            Text("已选择 Lanerc 资源；不代表已解析或开始播放。", style = MaterialTheme.typography.bodySmall)
        }
    }
}
