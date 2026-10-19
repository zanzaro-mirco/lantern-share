package lantern.connectivity

import lantern.domain.GroupAdoptionRepository
import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.LocalGroupMembership
import java.util.Base64

internal fun prepareLocalMembership(identity: Identity, repository: GroupAdoptionRepository): GroupMembershipEvidence =
    GroupRootAdoptionJournalInspector.withVerifier { verify ->
        LocalGroupMembership.prepare(repository, identity.id,
            GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(identity.certificate.encoded)), verify)
    }

internal fun verifyPeerMembership(evidence: GroupMembershipEvidence, anchor: GroupTrustAnchor, peerId: String): Boolean =
    GroupRootAdoptionJournalInspector.withVerifier { evidence.verify(anchor, peerId, it) }
