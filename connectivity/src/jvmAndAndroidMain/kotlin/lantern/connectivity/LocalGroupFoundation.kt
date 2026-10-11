package lantern.connectivity

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupFoundationDraft

/** OS randomness and the existing identity only; no persistence or implicit group adoption. */
internal fun prepareLocalGroupFoundation(
    identity: Identity,
    currentAnchor: GroupTrustAnchor?,
): GroupFoundationDraft = GroupFoundationDraft.prepare(identity.id, currentAnchor, ::randomNonce)
