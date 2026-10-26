package lantern.connectivity

import java.io.Closeable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Keeps potentially blocking TLS close notifications away from UI callers. */
internal class AsyncResourceCloser(private val scope: CoroutineScope) {
    fun close(resource: Closeable): Job = closeAll(listOf(resource))

    /**
     * Copies [resources] at the call, so a live concurrent set may lose elements meanwhile: Kotlin's
     * `toList()` reads `size` and then `first()`, and throws when a handler removes its socket in between.
     */
    fun closeAll(resources: Collection<Closeable>): Job {
        val snapshot = ArrayList(resources)
        return scope.launch {
            snapshot.forEach { resource -> runCatching { resource.close() } }
        }
    }
}
