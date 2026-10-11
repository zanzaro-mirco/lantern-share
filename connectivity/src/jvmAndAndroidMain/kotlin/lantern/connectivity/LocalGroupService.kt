package lantern.connectivity

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import lantern.domain.LocalGroupController
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupRepository
import lantern.domain.LocalGroupState
import lantern.protocol.Wire
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns only local foundation work, not transport, sessions or repository lifetime.
 * The app supplies the same immutable OS identity as its Node and must close this service
 * before closing the database. Identity replacement requires recreating both owners.
 * UI entry points only reserve state/launch IO; opening the screen never creates a group.
 */
class LocalGroupService(
    private val identity: Identity,
    private val repository: LocalGroupRepository,
) : LocalGroupController, AutoCloseable {
    private val mutable = MutableStateFlow<LocalGroupState>(LocalGroupState.Loading)
    override val state = mutable.asStateFlow()
    private val closed = AtomicBoolean(false)
    private val lifecycleGate = Any()
    private val lifetime = SupervisorJob()
    private val scope = CoroutineScope(lifetime + Dispatchers.IO)

    init { load() }

    override fun create() {
        if (closed.get() || !mutable.compareAndSet(LocalGroupState.Empty, LocalGroupState.Creating)) return
        scope.launch {
            try {
                ensureActive()
                val owner = LocalGroupFoundation(identity)
                val ticket = owner.prepare(repository.localGroup())
                ensureActive()
                // After handoff the synchronous transaction may finish even during close.
                // Close joins the worker before the app releases the driver; no stale UI update.
                if (ticket != null) {
                    val handedOff = synchronized(lifecycleGate) {
                        ensureActive()
                        !closed.get()
                    }
                    if (!handedOff) return@launch
                    owner.commit(ticket, identity, repository)
                }
                val persisted = readState()
                check(persisted != LocalGroupState.Empty) { "Foundation missing after commit handoff" }
                mutable.compareAndSet(LocalGroupState.Creating, persisted)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // A write error can have an uncertain acknowledgement. Never restore Empty
                // or replay here: only an explicit read-only reload can recover durable state.
                mutable.compareAndSet(LocalGroupState.Creating, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
            }
        }
    }

    override fun reload() {
        if (closed.get()) return
        val previous = mutable.value
        if (previous !is LocalGroupState.Failed) return
        if (mutable.compareAndSet(previous, LocalGroupState.Loading)) load()
    }

    private fun load() {
        scope.launch {
            try {
                ensureActive()
                mutable.compareAndSet(LocalGroupState.Loading, readState())
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                mutable.compareAndSet(LocalGroupState.Loading, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
            }
        }
    }

    private fun readState(): LocalGroupState {
        val anchor = repository.localGroup() ?: return LocalGroupState.Empty
        if (!Wire.isFingerprint(anchor.groupId) || !Wire.isFingerprint(anchor.founderId)) {
            return LocalGroupState.Failed(LocalGroupFailure.INVALID_ROOT)
        }
        if (anchor.founderId != identity.id) return LocalGroupState.Failed(LocalGroupFailure.IDENTITY_MISMATCH)
        return LocalGroupState.Founded(anchor)
    }

    override fun close() {
        synchronized(lifecycleGate) {
            if (closed.compareAndSet(false, true)) mutable.value = LocalGroupState.Closed
        }
        // Every closer must join, including a second close concurrent with an active commit.
        runBlocking { lifetime.cancelAndJoin() }
    }
}
