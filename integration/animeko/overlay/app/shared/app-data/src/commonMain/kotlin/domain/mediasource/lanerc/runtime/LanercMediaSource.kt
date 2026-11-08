// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.runtime

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.Serializable
import io.ktor.http.Url
import kotlinx.serialization.json.JsonPrimitive
import me.him188.ani.app.domain.mediasource.codec.*
import me.him188.ani.app.domain.mediasource.codec.MediaSourceTier
import me.him188.ani.app.domain.mediasource.lanerc.core.*
import me.him188.ani.datasources.api.*
import me.him188.ani.datasources.api.matcher.ApiVideoResolver
import me.him188.ani.datasources.api.matcher.WebVideo
import me.him188.ani.datasources.api.paging.*
import me.him188.ani.datasources.api.source.*
import me.him188.ani.datasources.api.topic.*
import me.him188.ani.utils.ktor.ScopedHttpClient
import me.him188.ani.utils.platform.currentTimeMillis

@OptIn(DontForgetToRegisterCodec::class)
@Serializable
data class LanercMediaSourceArguments(
    override val name: String = "Lanerc 动态内置源",
    val backendOverride: String = "",
    override val tier: MediaSourceTier = MediaSourceTier.Fallback,
) : MediaSourceArguments

object LanercMediaSourceCodec : DefaultMediaSourceCodec<LanercMediaSourceArguments>(
    LanercMediaSource.FactoryId, LanercMediaSourceArguments::class, 1, LanercMediaSourceArguments.serializer(),
)

/** Native Lanerc source, participating in Animeko browsing and API video resolution. */
class LanercMediaSource(
    override val mediaSourceId: String,
    config: MediaSourceConfig,
    private val settings: LanercSettingsStore,
) : HttpMediaSource(), ApiVideoResolver {
    companion object {
        val FactoryId = FactoryId("lanerc-native")
        const val BUILTIN_ID = "lanerc.builtin"
        private const val VIRTUAL = "https://lanerc.invalid/"
    }
    val arguments = config.deserializeArgumentsOrNull(LanercMediaSourceArguments.serializer()) ?: LanercMediaSourceArguments()
    @Suppress("DEPRECATION")
    val session = LanercSourceSession(mediaSourceId, arguments, settings, config.proxy)
    override val kind = MediaSourceKind.WEB
    override val location = MediaSourceLocation.Online
    override val supportsBrowsing = true
    override val info = MediaSourceInfo(arguments.name, "Lanerc 原生动态 API；与 Animeko 其他源并行", tier = arguments.tier)

    class Factory(private val settings: LanercSettingsStore) : MediaSourceFactory {
        override val factoryId get() = FactoryId
        override val info = MediaSourceInfo("Lanerc 动态源", "原生动态 API、访客播放协议")
        override val allowMultipleInstances = true
        override fun create(mediaSourceId: String, config: MediaSourceConfig, client: ScopedHttpClient): MediaSource =
            LanercMediaSource(mediaSourceId, config, settings)
    }

    override suspend fun checkConnection(): ConnectionStatus = try {
        session.api().backend()
        ConnectionStatus.SUCCESS
    } catch (cancelled: CancellationException) { throw cancelled }
    catch (_: Exception) { ConnectionStatus.FAILED }

    override suspend fun searchSubjects(keyword: String): List<BrowseSubject> {
        if (keyword.isBlank()) return emptyList()
        val result = session.api().json(LanercEndpoints.SEARCH, linkedMapOf("keyword" to JsonPrimitive(keyword.trim())))
        return LanercCatalog.search(result).map { BrowseSubject(it.title, "${VIRTUAL}subject/${it.id}") }
    }
    private fun subjectId(subject: BrowseSubject): String = subject.url.removePrefix("${VIRTUAL}subject/").also {
        require(subject.url.startsWith("${VIRTUAL}subject/") && Regex("[A-Za-z0-9_-]{1,128}").matches(it)) { "Invalid Lanerc subject identity" }
    }
    override suspend fun browseSubject(subject: BrowseSubject): List<BrowseChannel> {
        val root = session.api().json(LanercEndpoints.DETAIL_PREFIX + subjectId(subject))
        val lines = LanercCatalog.lines(root)
        return lines.mapIndexed { index, line ->
            val name = if (lines.count { it.id == line.id } > 1) "${line.id} #${index + 1}" else line.id
            BrowseChannel(name, label = line.name, episodes = line.episodes.mapIndexed { episodeIndex, episode ->
                BrowseEpisode(episode.title, "${VIRTUAL}resource/${episode.id}?vod_index=${episodeIndex + 1}", parseSort(episode.title))
            })
        }
    }
    private fun parseSort(title: String): EpisodeSort? = Regex("^\\s*(?:第)?([0-9]+(?:\\.5)?)(?:集|话)?\\s*$")
        .matchEntire(title)?.groupValues?.get(1)?.let { EpisodeSort(it) }

    override fun createMedia(subject: BrowseSubject, channelName: String?, episode: BrowseEpisode, episodeSort: EpisodeSort?): Media {
        val id = episode.url.substringBefore('?').removePrefix("${VIRTUAL}resource/")
        val vodIndex = Url(episode.url).parameters["vod_index"]?.toIntOrNull()
        require(vodIndex != null && vodIndex > 0) { "Missing native danmaku episode index" }
        require(episode.url.startsWith("${VIRTUAL}resource/") && LanercIdentifiers.validResource(id))
        return DefaultMedia(
            mediaId = "$mediaSourceId.${subjectId(subject)}.${LanercUri.component(channelName.orEmpty())}.$id",
            mediaSourceId = mediaSourceId,
            originalUrl = episode.url,
            download = ResourceLocation.WebVideo(episode.url, apiParameters = mapOf("resource_id" to id, "vod_id" to subjectId(subject), "vod_index" to vodIndex.toString())),
            originalTitle = "${subject.name} ${episode.name}", publishedTime = 0L,
            properties = MediaProperties(subjectName = subject.name, episodeName = episode.name,
                subtitleLanguageIds = emptyList(), resolution = "", alliance = channelName.orEmpty(),
                size = FileSize.Unspecified, subtitleKind = null),
            episodeRange = episodeSort?.let { EpisodeRange.single(it) }, location = MediaSourceLocation.Online, kind = MediaSourceKind.WEB,
        )
    }
    override suspend fun fetch(query: MediaFetchRequest): SizedSource<MediaMatch> = SinglePagePagedSource {
        flow {
            val names = query.subjectNames.distinct().take(3)
            val exactNames = names.map { ParallelSourceSearch.normalizedTitle(it) }.toSet()
            val seen = mutableSetOf<String>()
            for (keyword in names) for (subject in searchSubjects(keyword)) {
                if (ParallelSourceSearch.normalizedTitle(subject.name) !in exactNames || !seen.add(subject.url)) continue
                for (channel in browseSubject(subject)) for (episode in channel.episodes) {
                    emit(MediaMatch(createMedia(subject, channel.name, episode, episode.episodeSort), MatchKind.FUZZY))
                }
            }
        }
    }
    private fun communityIdentity(media: Media): LanercCommunityIdentity = LanercCommunity.identity(
        mediaSourceId, media.mediaSourceId, media.originalUrl,
        (media.download as? ResourceLocation.WebVideo)?.apiParameters ?: error("Missing native source metadata"),
    )
    suspend fun readComments(media: Media, page: Int = 1): LanercCommentPage =
        session.api().comments(communityIdentity(media).vid, page)

    suspend fun readBarrages(media: Media): List<LanercBarrage> {
        val identity = communityIdentity(media)
        return session.api().barrages(identity.vid, identity.vodIndex)
    }

    override suspend fun resolveApiVideo(media: Media): WebVideo? {
        val parameters = (media.download as? ResourceLocation.WebVideo)?.apiParameters ?: return null
        val resource = parameters["resource_id"] ?: return null
        val api = session.api()
        val origin = LanercUri.origin(api.backend())
        val credential = settings.credential(mediaSourceId, origin, currentTimeMillis())
            ?: error("请在设置 → 数据源 → Lanerc 完成人工访客验证码，再重试播放")
        val url = api.play(resource, credential).playUrl
        require(publicHttpsUrl(url)) { "Lanerc 返回了无效或不安全的播放地址" }
        return WebVideo(url, emptyMap()) // API credentials are never forwarded to the media CDN.
    }
    override fun close() { session.close(); super.close() }
}
