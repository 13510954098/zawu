// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.*
import me.him188.ani.app.domain.mediasource.lanerc.core.*

/** Source settings are exportable; this store holds only mode and device-sealed private material. */
class LanercSettingsStore(private val preferences: DataStore<Preferences>) {
    private val modeKey = stringPreferencesKey("lanerc.mode.v1")
    val mode = preferences.data.map { values -> SourceMode.entries.firstOrNull { it.name == values[modeKey] } ?: SourceMode.ANIMEKO }
    suspend fun setMode(mode: SourceMode) { preferences.edit { it[modeKey] = mode.name } }
    private fun materialKey(sourceId: String) = stringPreferencesKey("lanerc.protocol.$sourceId")
    internal suspend fun sealedMaterial(sourceId: String): String =
        preferences.data.first()[materialKey(sourceId)] ?: error("请在 Lanerc 源设置中导入本机协议材料")

    suspend fun hasMaterial(sourceId: String): Boolean = preferences.data.first()[materialKey(sourceId)] != null
    suspend fun importMaterial(sourceId: String, raw: String) {
        require(raw.length <= 65536) { "材料文件过大" }
        parseMaterial(raw) // Validate all required fields before replacing any previous material.
        val sealed = LanercPlatform.seal("protocol:$sourceId", raw)
        preferences.edit { it[materialKey(sourceId)] = sealed }
    }
    internal fun unsealMaterial(sourceId: String, sealed: String): LanercSecrets = try {
        parseMaterial(LanercPlatform.unseal("protocol:$sourceId", sealed))
    } catch (_: Exception) { error("本机协议材料无法读取，请重新导入") }

    private fun credentialKey(sourceId: String, origin: String) = stringPreferencesKey("lanerc.guest.$sourceId.$origin")
    suspend fun saveCredential(sourceId: String, credential: LanercGuestCredential) {
        val scope = "credential:$sourceId:${credential.origin}"
        val raw = buildJsonObject { put("origin", credential.origin); put("value", credential.value); put("expires", credential.expiresAtMillis) }.toString()
        val sealed = LanercPlatform.seal(scope, raw)
        preferences.edit { it[credentialKey(sourceId, credential.origin)] = sealed }
    }
    suspend fun credential(sourceId: String, origin: String, nowMillis: Long): LanercGuestCredential? {
        val sealed = preferences.data.first()[credentialKey(sourceId, origin)] ?: return null
        return try {
            val raw = Json.parseToJsonElement(LanercPlatform.unseal("credential:$sourceId:$origin", sealed)).jsonObject
            val saved = LanercGuestCredential(raw.getValue("origin").jsonPrimitive.content, raw.getValue("value").jsonPrimitive.content, raw.getValue("expires").jsonPrimitive.long)
            saved.takeIf { it.origin == origin && it.value.isNotBlank() && it.expiresAtMillis > nowMillis }
        } catch (_: Exception) { null }
    }
    suspend fun clearPrivate(sourceId: String) {
        preferences.edit { values ->
            values.asMap().keys.filter { it.name == materialKey(sourceId).name || it.name.startsWith("lanerc.guest.$sourceId.") }
                .forEach { values.remove(it) }
        }
    }

    private fun parseMaterial(raw: String): LanercSecrets {
        val root = Json.parseToJsonElement(raw).jsonObject
        fun key(section: String): ByteArray {
            val hex = root.getValue(section).jsonObject.getValue("key_hex").jsonPrimitive.content
            require(Regex("[a-fA-F0-9]{64}").matches(hex)) { "Expected 32-byte key" }
            return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
        val suffix = root.getValue("request_signature").jsonObject.getValue("secret_suffix").jsonPrimitive.content
        val pairs = root.getValue("json_response_encryption").jsonObject.getValue("ordered_replacements").jsonArray.map {
            val pair = it.jsonArray
            require(pair.size == 2)
            pair[0].jsonPrimitive.content to pair[1].jsonPrimitive.content
        }
        require(pairs.size == 10) { "Expected native transport replacement table" }
        return LanercSecrets(suffix, key("response_encryption"), key("json_response_encryption"), key("bootstrap_txt_encryption"), pairs)
    }
}
