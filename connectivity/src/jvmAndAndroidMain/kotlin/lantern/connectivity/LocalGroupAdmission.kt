package lantern.connectivity

import lantern.domain.GroupAdoptionRepository
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.LocalGroupAdmission
import java.util.Base64

/** Same OS verifier as durable membership inspection; consumed by the live service owner. */
internal fun prepareLocalGroupAdmission(identity: Identity, repository: GroupAdoptionRepository, memberId: String): GroupAdmissionEvidence =
    GroupRootAdoptionJournalInspector.withVerifier { verify ->
        LocalGroupAdmission.prepareSigned(repository, identity.id, memberId,
            GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(identity.certificate.encoded)),
            identity::sign, verify)
    }
