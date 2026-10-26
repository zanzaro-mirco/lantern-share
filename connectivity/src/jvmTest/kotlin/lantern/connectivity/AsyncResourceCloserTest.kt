package lantern.connectivity

import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking

class AsyncResourceCloserTest {
    @Test
    fun closeRunsOnOwnedIoDispatcherInsteadOfCallingThread() {
        val executor = Executors.newSingleThreadExecutor { task -> Thread(task, "lantern-close-io") }
        val dispatcher = executor.asCoroutineDispatcher()
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val callingThread = Thread.currentThread().name
        var closeThread = ""
        try {
            val job = AsyncResourceCloser(scope).close(Closeable { closeThread = Thread.currentThread().name })
            runBlocking { job.join() }
            assertNotEquals(callingThread, closeThread)
            assertTrue(closeThread.startsWith("lantern-close-io"))
        } finally {
            dispatcher.close()
            executor.shutdownNow()
        }
    }

    @Test
    fun closeAllCopiesLiveSetWhenHandlerRemovesItsSocketBetweenSizeAndIteration() {
        val closed = mutableListOf<String>()
        fun resource(name: String) = Closeable { synchronized(closed) { closed += name } }
        // Node's live socket set: a handler's finally removes the only socket right after size is read.
        val racing = object : AbstractMutableSet<Closeable>() {
            val live: MutableSet<Closeable> = ConcurrentHashMap.newKeySet()
            override val size: Int get() = live.size.also { live.clear() }
            override fun iterator() = live.iterator()
            override fun add(element: Closeable) = live.add(element)
        }
        racing.add(resource("removed"))
        assertFailsWith<NoSuchElementException> { racing.toList() }

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            racing.add(resource("removed"))
            val job = AsyncResourceCloser(scope).closeAll(racing)
            racing.add(resource("later")) // Accepted after the call: belongs to the next selection.
            runBlocking { job.join() }
            assertEquals(emptyList(), synchronized(closed) { closed.toList() })

            val sockets: MutableSet<Closeable> = ConcurrentHashMap.newKeySet()
            sockets += resource("a"); sockets += resource("b")
            val drain = AsyncResourceCloser(scope).closeAll(sockets)
            sockets += resource("c")
            runBlocking { drain.join() }
            assertEquals(setOf("a", "b"), synchronized(closed) { closed.toSet() })
        } finally {
            scope.cancel()
        }
    }
}
