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
     * `toList()` and `buildList { addAll(resources) }` trust `size` before iterating, and can throw
     * when a handler removes its socket in between. Java's ArrayList copies through `toArray()`.
     * [first] is closed before the copied resources, e.g. a listener that must stop accepting sockets.
     */
    fun closeAll(resources: Collection<Closeable>, first: Closeable? = null): Job {
        val snapshot = ArrayList<Closeable>()
        first?.let(snapshot::add)
        snapshot.addAll(resources)
        return scope.launch {
            snapshot.forEach { resource -> runCatching { resource.close() } }
        }
    }
}
