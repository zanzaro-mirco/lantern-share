package lantern.connectivity

import java.io.Closeable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Keeps potentially blocking TLS close notifications away from UI callers. */
internal class AsyncResourceCloser(private val scope: CoroutineScope) {
    fun close(resource: Closeable): Job = closeAll(listOf(resource))

    fun closeAll(resources: Collection<Closeable>): Job = scope.launch {
        resources.forEach { resource -> runCatching { resource.close() } }
    }
}
