// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull

enum class SourceMode { ANIMEKO, LANERC, BOTH }
enum class SourceFamily { ANIMEKO, LANERC }

/** IDs are namespaced by family and source, never by title. */
data class SourceSearchItem(
    val sourceId: String,
    val subjectId: String,
    val title: String,
    val family: SourceFamily,
    val aliases: List<String> = emptyList(),
)

interface ParallelSearchSource {
    val sourceId: String
    val family: SourceFamily
    suspend fun search(keyword: String): List<SourceSearchItem>
}

sealed interface SourceSearchEvent {
    data class Results(val sourceId: String, val family: SourceFamily, val items: List<SourceSearchItem>) : SourceSearchEvent
    /** Deliberately excludes exception messages, URLs, tokens and raw response data. */
    data class Failure(val sourceId: String, val family: SourceFamily, val reason: Reason) : SourceSearchEvent
    enum class Reason { TIMEOUT, SOURCE_ERROR }
}

/**
 * Independent source failures, bounded concurrency, incremental results and structured cancellation.
 * Caller uses flatMapLatest on query changes to cancel stale searches.
 * Keeps upstream Animeko's matcher intact; title score is only for this result surface.
 */
class ParallelSourceSearch(
    private val concurrency: Int = 4,
    private val timeoutMillis: Long = 12_000,
) {
    init {
        require(concurrency in 1..16)
        require(timeoutMillis in 1..120_000)
    }

    fun search(keyword: String, mode: SourceMode, sources: List<ParallelSearchSource>): Flow<SourceSearchEvent> = channelFlow {
        val query = keyword.trim()
        if (query.isEmpty()) return@channelFlow
        // Snapshot and validate IDs before starting any work; never mix one source's results into another.
        val selected = sources.filter { mode == SourceMode.BOTH || mode.name == it.family.name }
        require(selected.map { it.family to it.sourceId }.distinct().size == selected.size) { "Duplicate source identity" }
        val semaphore = Semaphore(concurrency)
        supervisorScope {
            for (source in selected) launch {
                semaphore.withPermit {
                    try {
                        val items = withTimeoutOrNull(timeoutMillis) { source.search(query) }
                        if (items == null) {
                            send(SourceSearchEvent.Failure(source.sourceId, source.family, SourceSearchEvent.Reason.TIMEOUT))
                        } else {
                            require(items.all { it.sourceId == source.sourceId && it.family == source.family }) { "Source provenance mismatch" }
                            val ranked = items.distinctBy { it.subjectId }.sortedWith(
                                compareByDescending<SourceSearchItem> { titleScore(query, it) }
                                    .thenBy { it.title }.thenBy { it.subjectId },
                            )
                            send(SourceSearchEvent.Results(source.sourceId, source.family, ranked))
                        }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        send(SourceSearchEvent.Failure(source.sourceId, source.family, SourceSearchEvent.Reason.SOURCE_ERROR))
                    }
                }
            }
        }
    }

    companion object {
        /** Width/case/spacing normalization preserves digits and season distinctions. */
        fun normalizedTitle(text: String): String = buildString {
            for (char in text.lowercase()) {
                val normalized = if (char.code in 0xff01..0xff5e) (char.code - 0xfee0).toChar() else char
                if (normalized.isLetterOrDigit()) append(normalized.lowercaseChar())
            }
        }

        fun titleScore(query: String, item: SourceSearchItem): Int {
            val needle = normalizedTitle(query)
            if (needle.isEmpty()) return 0
            return (listOf(item.title) + item.aliases).maxOf { title ->
                val haystack = normalizedTitle(title)
                when {
                    haystack == needle -> 1000
                    haystack.startsWith(needle) -> 700
                    needle in haystack -> 500
                    else -> 0
                }
            }
        }
    }
}
