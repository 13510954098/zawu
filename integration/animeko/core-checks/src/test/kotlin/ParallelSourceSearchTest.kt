// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.*

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ParallelSourceSearchTest {
    private fun source(id: String, family: SourceFamily, action: suspend () -> List<SourceSearchItem>) = object : ParallelSearchSource {
        override val sourceId = id
        override val family = family
        override suspend fun search(keyword: String) = action()
    }
    private fun item(id: String, family: SourceFamily, subject: String = "1", title: String = "Title") =
        SourceSearchItem(id, subject, title, family)

    @Test fun `both modes run and identical titles keep source provenance`() = runTest {
        val sources = SourceFamily.entries.map { family -> source("same-id", family) { listOf(item("same-id", family)) } }
        val events = ParallelSourceSearch().search("Title", SourceMode.BOTH, sources).toList()
        assertEquals(2, events.size)
        assertEquals(SourceFamily.entries.toSet(), events.map { (it as SourceSearchEvent.Results).family }.toSet())
    }

    @Test fun `mode filters do not call the other family`() = runTest {
        val sources = listOf(
            source("a", SourceFamily.ANIMEKO) { listOf(item("a", SourceFamily.ANIMEKO)) },
            source("l", SourceFamily.LANERC) { error("Must not execute") },
        )
        assertEquals(1, ParallelSourceSearch().search("Title", SourceMode.ANIMEKO, sources).toList().size)
    }

    @Test fun `source failures do not suppress healthy results`() = runTest {
        val events = ParallelSourceSearch().search("Title", SourceMode.BOTH, listOf(
            source("bad", SourceFamily.LANERC) { error("private-error-marker") },
            source("good", SourceFamily.ANIMEKO) { listOf(item("good", SourceFamily.ANIMEKO)) },
        )).toList()
        assertEquals(1, events.filterIsInstance<SourceSearchEvent.Results>().size)
        assertEquals(1, events.filterIsInstance<SourceSearchEvent.Failure>().size)
        assertFalse(events.toString().contains("private-error-marker"))
    }

    @Test fun `slow sources time out without blocking completed results`() = runTest {
        val events = ParallelSourceSearch(timeoutMillis = 20).search("Title", SourceMode.LANERC, listOf(
            source("slow", SourceFamily.LANERC) { delay(100); emptyList() },
            source("fast", SourceFamily.LANERC) { listOf(item("fast", SourceFamily.LANERC)) },
        )).toList()
        assertIs<SourceSearchEvent.Results>(events.first())
        assertEquals(SourceSearchEvent.Reason.TIMEOUT, (events.last() as SourceSearchEvent.Failure).reason)
    }

    @Test fun `concurrency is bounded`() = runTest {
        var running = 0
        var maximum = 0
        val sources = (1..12).map { n -> source("$n", SourceFamily.LANERC) {
            running++
            maximum = maxOf(maximum, running)
            delay(10)
            running--
            emptyList()
        } }
        ParallelSourceSearch(concurrency = 3).search("Title", SourceMode.BOTH, sources).toList()
        assertEquals(3, maximum)
        assertEquals(0, running)
    }

    @Test fun `parent cancellation reaches source without failure event`() = runTest {
        var cancelled = false
        val events = mutableListOf<SourceSearchEvent>()
        val job = launch {
            ParallelSourceSearch().search("Title", SourceMode.BOTH, listOf(source("a", SourceFamily.LANERC) {
                try { awaitCancellation() } finally { cancelled = true }
            })).collect { events += it }
        }
        runCurrent()
        job.cancel()
        job.join()
        assertTrue(cancelled)
        assertTrue(events.isEmpty())
    }

    @Test fun `blank query does not execute sources`() = runTest {
        val events = ParallelSourceSearch().search("  ", SourceMode.BOTH,
            listOf(source("a", SourceFamily.LANERC) { error("Must not execute") })).toList()
        assertTrue(events.isEmpty())
    }

    @Test fun `foreign provenance is rejected`() = runTest {
        val result = ParallelSourceSearch().search("x", SourceMode.BOTH,
            listOf(source("a", SourceFamily.LANERC) { listOf(item("b", SourceFamily.LANERC)) })).toList().single()
        assertIs<SourceSearchEvent.Failure>(result)
    }

    @Test fun `ranking respects aliases and does not erase season digits`() = runTest {
        val records = listOf(
            item("a", SourceFamily.LANERC, "2", "Title 2"),
            item("a", SourceFamily.LANERC, "1", "Ｔｉｔｌｅ"),
            SourceSearchItem("a", "3", "Other", SourceFamily.LANERC, aliases = listOf("Title")),
            item("a", SourceFamily.LANERC, "1", "duplicate"),
        )
        val result = ParallelSourceSearch().search("Title", SourceMode.BOTH,
            listOf(source("a", SourceFamily.LANERC) { records })).toList().single() as SourceSearchEvent.Results
        assertEquals(3, result.items.size)
        assertEquals("2", result.items.last().subjectId)
        assertNotEquals(ParallelSourceSearch.normalizedTitle("Title 2"), ParallelSourceSearch.normalizedTitle("Title"))
    }
}
