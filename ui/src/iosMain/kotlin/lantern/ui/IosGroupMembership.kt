package lantern.ui

import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.protocol.GroupMembershipEvidenceFrameDecoder
import lantern.protocol.LocalGroupMembership

/** Opaque untrusted proof, not a reusable permission to open a session or write trust. */
class IosGroupMembershipEvidence internal constructor(internal val evidence: GroupMembershipEvidence) {
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES

    @Throws(Exception::class)
    fun framedBytes(): ByteArray = GroupMembershipEvidenceCodec.encode(evidence).let {
        GroupMembershipEvidenceCodec.header(it.size) + it
    }

    /** Negotiated routing/order only, never membership authority. Frozen offers from this TLS. */
    @Throws(Exception::class)
    fun sendsFirst(offers: IosHandshakeV1Offers): Boolean = evidence.sendsFirst(offers.offers)

    /** expectedGroup/founder come from LOCAL durable storage; peer comes from this mutual TLS. */
    @Throws(Exception::class)
    fun verify(
        expectedGroup: String, expectedFounder: String, authenticatedPeerIdentity: String,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ): Boolean = evidence.verify(GroupTrustAnchor(expectedGroup, expectedFounder), authenticatedPeerIdentity) { cert, bytes, signature ->
        checkNotNull(verifyCertificateSignature(IosGroupAdmissionCertificate(cert), bytes, signature)) {
            "OS membership verification failed"
        }
    }
}

object IosLocalGroupMembership {
    val maximumDerBytes: Int get() = GroupAdmissionCertificate.MAX_DER_BYTES
    val feature: String get() = GroupMembershipEvidenceCodec.FEATURE

    @Throws(Exception::class)
    fun prepare(
        persistence: IosPersistence, identityId: String, certificateDer: String,
        verifyCertificateSignature: (IosGroupAdmissionCertificate, ByteArray, String) -> Boolean?,
    ): IosGroupMembershipEvidence = IosGroupMembershipEvidence(LocalGroupMembership.prepare(
        persistence.groupAdoptions, identityId, GroupAdmissionCertificate(identityId, certificateDer),
        { cert, bytes, signature ->
            checkNotNull(verifyCertificateSignature(IosGroupAdmissionCertificate(cert), bytes, signature)) {
                "OS membership verification failed"
            }
        },
    ))
}

class IosGroupMembershipRead internal constructor(val consumedBytes: Int, val evidence: IosGroupMembershipEvidence?)

/** Exact read budgets and all framing rules stay shared. No transport/DB/lifecycle ownership. */
class IosGroupMembershipDecoder {
    private val decoder = GroupMembershipEvidenceFrameDecoder()

    @Throws(Exception::class)
    fun nextReadBytes(): Int = decoder.nextReadBytes

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): IosGroupMembershipRead = decoder.accept(chunk).let {
        IosGroupMembershipRead(it.consumedBytes, it.evidence?.let(::IosGroupMembershipEvidence))
    }

    @Throws(Exception::class)
    fun finish() { decoder.finish() }

    fun cancel() = decoder.close()
}
