package lantern.connectivity

import java.io.Closeable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
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
}
