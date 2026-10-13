package lantern.protocol

/**
 * Public evidence retained after both confirmations and the successful local transport write.
 * Not membership, a reusable consent ticket or a durable/distributed commit acknowledgement.
 * The receiving commit owner must preserve liveness and recheck identity/group/block state.
 * After restart these attestations require full context/signature validation and the future
 * recovery protocol; retaining or decoding their bytes alone never authorizes a peer.
 */
class GroupAdmissionConfirmationReceipt internal constructor(
    comparisonBytes: ByteArray,
    val local: GroupAdmissionConfirmation,
    val remote: GroupAdmissionConfirmation,
) {
    private val comparisonContent = comparisonBytes.copyOf()

    init {
        require(local.sender == remote.recipient && local.recipient == remote.sender) {
            "Confirmation receipt requires opposite directions"
        }
    }

    fun comparisonBytes(): ByteArray = comparisonContent.copyOf()
}
