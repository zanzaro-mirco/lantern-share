package lantern.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import lantern.domain.LocalGroupController
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState
import lantern.protocol.localGroupPresentation
import lantern.protocol.GroupAdmissionCertificate

enum class IosLocalGroupDisplayPhase { LOADING, EMPTY, CREATING, FOUNDED, FAILED, CLOSED, ADOPTED }
data class IosLocalGroupDisplay(val phase: IosLocalGroupDisplayPhase, val groupId: String, val failure: String)

/**
 * Shared UI state, no OS IO. Swift callbacks enqueue work on the owning service queue.
 * CAS reserves one operation before dispatch; completion can never revive a closed controller.
 * The Swift owner keeps itself/database alive until queued synchronous operations finish.
 */
class IosLocalGroupController(
    private val requestCreate: () -> Unit,
    private val requestReload: () -> Unit,
) : LocalGroupController {
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES
    private val mutable = MutableStateFlow<LocalGroupState>(LocalGroupState.Loading)
    override val state = mutable.asStateFlow()

    fun snapshot(): IosLocalGroupDisplay = when (val current = mutable.value) {
        LocalGroupState.Loading -> view(IosLocalGroupDisplayPhase.LOADING)
        LocalGroupState.Empty -> view(IosLocalGroupDisplayPhase.EMPTY)
        LocalGroupState.Creating -> view(IosLocalGroupDisplayPhase.CREATING)
        is LocalGroupState.Founded -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.FOUNDED, current.anchor.groupId, "")
        is LocalGroupState.Adopted -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.ADOPTED, current.anchor.groupId, "")
        is LocalGroupState.Failed -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.FAILED, "", current.reason.name)
        LocalGroupState.Closed -> view(IosLocalGroupDisplayPhase.CLOSED)
    }

    override fun create() {
        if (mutable.compareAndSet(LocalGroupState.Empty, LocalGroupState.Creating)) requestCreate()
    }

    override fun reload() {
        val previous = mutable.value
        if (previous is LocalGroupState.Failed && mutable.compareAndSet(previous, LocalGroupState.Loading)) requestReload()
    }

    fun hasPendingCreation(): Boolean = mutable.value == LocalGroupState.Creating

    /** Foundation-only compatibility entry; adopted material fails closed without an OS verifier. */
    @Throws(Exception::class)
    fun loaded(identityId: String, persistence: IosPersistence) {
        loadedVerified(identityId, persistence) { _, _, _ -> false }
    }

    /**
     * Called on the Swift service queue after opening stores or explicit reload. OS callback returns
     * null on provider/parser error; no state is published before it succeeds. No pending journal read.
     */
    @Throws(Exception::class)
    fun loadedVerified(
        identityId: String, persistence: IosPersistence,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ) {
        if (mutable.value != LocalGroupState.Loading) return
        mutable.compareAndSet(LocalGroupState.Loading, readState(identityId, persistence, verifyCertificateSignature))
    }

    /** Read durable state after handoff, not a supplied draft or caller's success boolean. */
    @Throws(Exception::class)
    fun created(identityId: String, persistence: IosPersistence) {
        createdVerified(identityId, persistence) { _, _, _ -> false }
    }

    @Throws(Exception::class)
    fun createdVerified(
        identityId: String, persistence: IosPersistence,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ) {
        if (!hasPendingCreation()) return
        val persisted = readState(identityId, persistence, verifyCertificateSignature)
        check(persisted != LocalGroupState.Empty) { "Foundation missing after commit handoff" }
        mutable.compareAndSet(LocalGroupState.Creating, persisted)
    }

    private fun readState(
        identityId: String, persistence: IosPersistence,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ): LocalGroupState {
        val committed = persistence.groupAdoptions.committedGroupAdoption()
        return localGroupPresentation(persistence.localGroups.localGroup(), identityId, committed) { cert, bytes, signature ->
            checkNotNull(verifyCertificateSignature(IosGroupAdmissionCertificate(cert), bytes, signature)) {
                "Certificate verification unavailable"
            }
        }
    }

    fun loadFailed() {
        mutable.compareAndSet(LocalGroupState.Loading, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
    }

    fun createFailed() {
        mutable.compareAndSet(LocalGroupState.Creating, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
    }

    fun close() { mutable.value = LocalGroupState.Closed }

    private fun view(phase: IosLocalGroupDisplayPhase) = IosLocalGroupDisplay(phase, "", "")
}
