package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.*

/** Native read-only DTOs. Position is deliberately retained, not guessed as an Animeko enum. */
data class LanercBarrage(val id: String, val color: String, val position: Int, val second: Double, val content: String)
data class LanercComment(val id: String, val createdAt: String, val nickname: String, val content: String, val replies: List<LanercComment>)
data class LanercCommentPage(val total: Int, val comments: List<LanercComment>)

object LanercCommunity {
    // APK 0x664dc4 / 0x664fa4. Both generations use the same record DTO.
    fun barrages(root: JsonElement): List<LanercBarrage> {
        val data = LanercCatalog.payload(root).jsonObject
        return listOf("new_barrages", "old_barrages").flatMap { key ->
            data.getValue(key).jsonArray.map { value ->
                val item = value.jsonObject
                val second = item.getValue("second").jsonPrimitive.double
                require(second.isFinite() && second >= 0 && second <= 604800) { "Invalid barrage time" }
                LanercBarrage(text(item, "id"), text(item, "bcolor"),
                    item.getValue("position").jsonPrimitive.int, second, text(item, "content"))
            }
        }.also { require(it.size <= 100000) { "Too many barrages" } }
    }

    // APK 0x4f3410 / 0x4f3d10 / 0x4f3e9c; data is JSON-serialized, not always ECB.
    fun comments(root: JsonElement): LanercCommentPage {
        val data = LanercCatalog.payload(root).jsonObject.getValue("vod_comment").jsonObject
        val total = data.getValue("total").jsonPrimitive.int
        require(total >= 0) { "Invalid comment count" }
        var remaining = 5000
        fun comment(value: JsonElement, depth: Int): LanercComment {
            require(depth <= 8 && --remaining >= 0) { "Comment nesting or count limit" }
            val item = value.jsonObject
            val replies = if (depth == 0) item["replies"] else null
            return LanercComment(text(item, if (depth == 0) "cid" else "id"), text(item, "created_at"), text(item, "nick_name"),
                text(item, "content"), if (replies == null || replies == JsonNull) emptyList()
                else replies.jsonArray.map { comment(it, depth + 1) })
        }
        return LanercCommentPage(total, data.getValue("comment").jsonArray.map { comment(it, 0) })
    }

    private fun text(item: JsonObject, key: String): String = item.getValue(key).jsonPrimitive.let {
        require(it != JsonNull) { "Null native community field" }
        it.content
    }
}
