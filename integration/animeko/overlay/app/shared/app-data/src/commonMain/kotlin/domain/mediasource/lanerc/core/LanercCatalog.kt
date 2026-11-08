// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.*

/** Native resource IDs are opaque URL-safe tokens, not short database IDs.
 * Real catalog tokens observed at 218..320 characters. Keep them bounded without truncating.
 */
object LanercIdentifiers {
    private val resourcePattern = Regex("[A-Za-z0-9_-]{1,4096}")
    fun validResource(value: String): Boolean = resourcePattern.matches(value)
}

data class LanercSubject(val id: String, val title: String)
data class LanercEpisode(val id: String, val title: String)
data class LanercLine(val id: String, val name: String, val episodes: List<LanercEpisode>)

/** Original APK field names. Unknown response shapes fail visibly instead of producing demo content. */
object LanercCatalog {
    fun payload(root: JsonElement): JsonElement {
        if (root !is JsonObject) return root
        val code = root["code"]?.jsonPrimitive?.intOrNull
        require("code" !in root || code == 200 || code == 201) { "Lanerc API did not return a successful code" }
        return root["data"] ?: root
    }
    fun search(root: JsonElement): List<LanercSubject> {
        val data = payload(root).jsonObject
        val list = data["search_vods"]?.jsonArray ?: error("Unsupported original search response shape")
        return list.map { value ->
            val item = value.jsonObject
            LanercSubject(id(item), text(item, "vod_name"))
        }.distinctBy { it.id }
    }
    fun lines(root: JsonElement): List<LanercLine> {
        val data = payload(root).jsonObject
        val list = data["video_play_list"]?.jsonArray ?: error("Unsupported original detail response shape")
        return list.map { value ->
            val item = value.jsonObject
            LanercLine(text(item, "player"), text(item, "name"), item.getValue("video").jsonArray.map { entry ->
                val episode = entry.jsonObject
                LanercEpisode(text(episode, "resource_id").also { require(LanercIdentifiers.validResource(it)) }, text(episode, "title"))
            })
        }
    }
    private fun id(item: JsonObject): String = text(item, "id").also {
        require(it.length <= 128 && Regex("[A-Za-z0-9_-]+").matches(it)) { "Invalid native resource identifier" }
    }
    private fun text(item: JsonObject, key: String): String = item.getValue(key).jsonPrimitive.content.also {
        require(it.isNotBlank()) { "Missing native catalog field" }
    }
}
