package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.serialization.json.*

/** Native read-only DTOs. Position is deliberately retained, not guessed as an Animeko enum. */
data class LanercBarrage(val id: String, val color: String, val position: Int, val second: Double, val content: String)
data class LanercComment(val id: String, val createdAt: String, val nickname: String, val content: String, val replies: List<LanercComment>)
data class LanercCommentPage(val total: Int, val comments: List<LanercComment>)

data class LanercRenderedBarrage(val id: String, val rgb: Int, val top: Boolean, val timeMillis: Long, val content: String)

data class LanercCommunityIdentity(val vid: String, val vodIndex: Int)

object LanercCommunity {
    /** APK 0x9231e8..0x923204: position == 1 selects enum top, every other value selects scroll.
     * Color conversion at 0x923030..0x9230fc removes # and parses hexadecimal ARGB.
     */
    fun render(barrage: LanercBarrage): LanercRenderedBarrage? {
        if (!barrage.second.isFinite() || barrage.second < 0 || barrage.second > 604800 || barrage.content.isBlank()) return null
        val hex = barrage.color.replace("#", "")
        if (!Regex("[0-9a-fA-F]{6}|[0-9a-fA-F]{8}").matches(hex)) return null
        val color = hex.toLongOrNull(16) ?: return null
        if (hex.length == 8 && color ushr 24 == 0L) return null
        return LanercRenderedBarrage(barrage.id, (color and 0xffffff).toInt(), barrage.position == 1,
            (barrage.second * 1000).toLong(), barrage.content.trim())
    }

    /** Only locally generated, source-bound native media metadata is accepted. */
    fun identity(sourceId: String, mediaSourceId: String, originalUrl: String, parameters: Map<String, String>): LanercCommunityIdentity {
        require(sourceId.isNotBlank() && sourceId == mediaSourceId) { "Community source mismatch" }
        val resource = parameters["resource_id"].orEmpty()
        val vid = parameters["vod_id"].orEmpty()
        val idPattern = Regex("[A-Za-z0-9_-]{1,128}")
        require(LanercIdentifiers.validResource(resource) && idPattern.matches(vid)) { "Invalid native identity" }
        val index = parameters["vod_index"]?.toIntOrNull()
        require(index != null && index > 0) { "Missing one-based native episode index" }
        require(originalUrl == "https://lanerc.invalid/resource/$resource?vod_index=$index") { "Native metadata mismatch" }
        return LanercCommunityIdentity(vid, index)
    }

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

/** Length-delimited namespaces prevent clearing `source` from also deleting `source.child`. */
object LanercStorageKeys {
    fun accountPrefix(sourceId: String): String = guestPrefix(sourceId).replaceFirst("lanerc.guest.v2.", "lanerc.account.v1.")
    fun account(sourceId: String, origin: String): String {
        require(LanercUri.origin(origin) == origin) { "Expected canonical backend origin" }
        return accountPrefix(sourceId) + origin
    }

    fun guestPrefix(sourceId: String): String {
        require(sourceId.isNotBlank() && sourceId.length <= 200) { "Invalid source identity" }
        return "lanerc.guest.v2.${sourceId.length}:$sourceId."
    }
    fun guest(sourceId: String, origin: String): String {
        require(LanercUri.origin(origin) == origin) { "Expected canonical backend origin" }
        return guestPrefix(sourceId) + origin
    }
}
