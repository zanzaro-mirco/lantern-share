package lantern.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import lantern.domain.LocalGroupExitController
import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState
import lantern.protocol.localGroupPresentation
import lantern.protocol.GroupAdmissionCertificate

enum class IosLocalGroupDisplayPhase { LOADING, EMPTY, CREATING, FOUNDED, FAILED, CLOSED, ADOPTED, LEAVING }
data class IosLocalGroupDisplay(val phase: IosLocalGroupDisplayPhase, val groupId: String, val failure: String)

/**
 * Shared UI state, no OS IO. Swift callbacks enqueue work on the owning service queue.
 * CAS reserves one operation before dispatch; completion can never revive a closed controller.
 * The Swift owner keeps itself/database alive until queued synchronous operations finish.
 */
class IosLocalGroupController(
    private val requestCreate: () -> Unit,
    private val requestReload: () -> Unit,
) : LocalGroupExitController {
    /** Installed once by the native owner before exposing the controller. No handler, no exit. */
    var leaveHandler: (() -> Unit)? = null
    private var exitAnchor: GroupTrustAnchor? = null
    private val exitRecoveryRequired = MutableStateFlow(false)
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES
    private val mutable = MutableStateFlow<LocalGroupState>(LocalGroupState.Loading)
    private val refreshPending = MutableStateFlow(false)
    override val state = mutable.asStateFlow()

    fun snapshot(): IosLocalGroupDisplay = when (val current = mutable.value) {
        LocalGroupState.Loading -> view(IosLocalGroupDisplayPhase.LOADING)
        LocalGroupState.Empty -> view(IosLocalGroupDisplayPhase.EMPTY)
        LocalGroupState.Creating -> view(IosLocalGroupDisplayPhase.CREATING)
        LocalGroupState.Leaving -> view(IosLocalGroupDisplayPhase.LEAVING)
        is LocalGroupState.Founded -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.FOUNDED, current.anchor.groupId, "")
        is LocalGroupState.Adopted -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.ADOPTED, current.anchor.groupId, "")
        is LocalGroupState.Failed -> IosLocalGroupDisplay(IosLocalGroupDisplayPhase.FAILED, "", current.reason.name)
        LocalGroupState.Closed -> view(IosLocalGroupDisplayPhase.CLOSED)
    }

    override fun create() {
        if (mutable.compareAndSet(LocalGroupState.Empty, LocalGroupState.Creating)) requestCreate()
    }

    /** Swift entry also used by native tests; shared UI passes the exact displayed state. */
    fun requestExit() { leave(mutable.value) }

    override fun leave(displayed: LocalGroupState) {
        val handler = leaveHandler ?: return
        val anchor = when (displayed) {
            is LocalGroupState.Founded -> displayed.anchor
            is LocalGroupState.Adopted -> displayed.anchor
            else -> return
        }
        if (mutable.value !== displayed || !mutable.compareAndSet(displayed, LocalGroupState.Leaving)) return
        exitAnchor = anchor
        handler()
    }

    fun hasPendingExit(): Boolean = mutable.value == LocalGroupState.Leaving

    /** Owner calls only after stopping LAN and draining all retired admission sessions. */
    @Throws(Exception::class)
    fun finishExit(identityId: String, persistence: IosPersistence) {
        if (!hasPendingExit()) return
        val anchor = checkNotNull(exitAnchor)
        check(persistence.localGroups.leaveLocalGroup(anchor, identityId)) { "Membership changed before exit" }
        check(persistence.localGroups.localGroup() == null && persistence.groupAdoptions.pendingGroupAdoption() == null)
        exitAnchor = null
        refreshPending.value = false
        mutable.compareAndSet(LocalGroupState.Leaving, LocalGroupState.Empty)
    }

    fun exitFailed() {
        exitRecoveryRequired.value = true
        exitAnchor = null
        refreshPending.value = false
        mutable.compareAndSet(LocalGroupState.Leaving, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
    }

    override fun reload() {
        val previous = mutable.value
        if (previous is LocalGroupState.Failed && mutable.compareAndSet(previous, LocalGroupState.Loading)) {
            exitRecoveryRequired.value = false
            requestReload()
        }
    }

    override fun refreshMembership() {
        if (exitRecoveryRequired.value) return
        refreshPending.value = true
        drainRefresh()
    }

    private fun drainRefresh() {
        while (refreshPending.value) {
            val current = mutable.value
            if (current == LocalGroupState.Closed || current == LocalGroupState.Loading || current == LocalGroupState.Creating || current == LocalGroupState.Leaving) return
            if (!mutable.compareAndSet(current, LocalGroupState.Loading)) continue
            refreshPending.value = false
            requestReload()
        }
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
        drainRefresh()
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
        drainRefresh()
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
        drainRefresh()
    }

    fun createFailed() {
        mutable.compareAndSet(LocalGroupState.Creating, LocalGroupState.Failed(LocalGroupFailure.STORAGE))
        drainRefresh()
    }

    fun close() { mutable.value = LocalGroupState.Closed }

    private fun view(phase: IosLocalGroupDisplayPhase) = IosLocalGroupDisplay(phase, "", "")
}
