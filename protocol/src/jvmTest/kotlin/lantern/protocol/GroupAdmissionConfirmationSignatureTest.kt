package lantern.protocol

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor

/** Real P-256, ephemeral keys and explicit fixture IDs; not TLS/certificates or physical confirmation. */
class GroupAdmissionConfirmationSignatureTest {
    private val group = "a".repeat(64)
    private val issuer = "b".repeat(64)
    private val member = "c".repeat(64)
    private val other = "d".repeat(64)
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text", "receipts"))
    private val issuerOffer = ProtocolHandshakeParticipant(issuer, "e".repeat(64), caps)
    private val memberOffer = ProtocolHandshakeParticipant(member, "f".repeat(64), caps)
    private val issuerKey = keyPair()
    private val memberKey = keyPair()
    private val claim = GroupAdmissionClaim(group, issuer, member)
    private val admission = SignedGroupAdmission(claim, sign(issuerKey, GroupAdmissionCodec.signedBytes(claim)))
    private val anchor = GroupTrustAnchor(group, issuer)
    private val context = context()

    @Test
    fun twoAttemptOwnersVerifyRealProofAndConfirmationsBeforeWriteCompletion() {
        val selectedAt = System.nanoTime() / 1_000_000
        fun owner(local: String, peer: String, peerKey: KeyPair) = GroupAdmissionConfirmationAttempt(
            context, local, peer, peer, selectedAt, { System.nanoTime() / 1_000_000 },
            { signer, bytes, encoded ->
                signer == issuer && verifySignature(issuerKey, bytes, encoded)
            },
            { bytes, encoded -> verifySignature(peerKey, bytes, encoded) },
        )
        val issuing = owner(issuer, member, memberKey)
        val joining = owner(member, issuer, issuerKey)
        assertTrue(issuing.prepare())
        assertTrue(joining.prepare())
        val issuerSign = assertNotNull(issuing.confirm(assertNotNull(issuing.comparison())))
        val memberSign = assertNotNull(joining.confirm(assertNotNull(joining.comparison())))
        val issuerSend = assertNotNull(issuing.signed(issuerSign, sign(issuerKey, issuerSign.bytes)))
        val memberSend = assertNotNull(joining.signed(memberSign, sign(memberKey, memberSign.bytes)))
        assertTrue(joining.receive(issuerSend.sender, issuerSend.recipient, issuerSend.signature))
        assertTrue(issuing.receive(memberSend.sender, memberSend.recipient, memberSend.signature))
        assertEquals(GroupAdmissionConfirmationState.Sending(true), issuing.state)
        assertEquals(GroupAdmissionConfirmationState.Sending(true), joining.state)
        assertTrue(issuing.sent(issuerSend))
        assertTrue(joining.sent(memberSend))
        assertEquals(GroupAdmissionConfirmationState.Confirmed, issuing.state)
        assertEquals(GroupAdmissionConfirmationState.Confirmed, joining.state)
        issuing.cancel()
        joining.transportClosed()
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.Cancelled), issuing.state)
        assertEquals(GroupAdmissionConfirmationState.Closed(GroupAdmissionConfirmationFailure.TransportClosed), joining.state)
    }

    @Test
    fun bothDirectionsRequireTheirOwnKeyAndCannotReuseBootstrapOrMembershipSignatures() {
        val fromIssuer = sign(issuerKey, context.approvalBytes(issuer))
        val fromMember = sign(memberKey, context.approvalBytes(member))
        assertEquals(GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation,
            verify(context, member, issuer, fromIssuer, issuerKey))
        assertEquals(GroupAdmissionConfirmationResult.VerifiedRemoteConfirmation,
            verify(context, issuer, member, fromMember, memberKey))
        assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
            verify(context, member, issuer, fromIssuer, memberKey))
        assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
            verify(context, issuer, member, fromIssuer, issuerKey))
        val oldBootstrap = sign(issuerKey, ProtocolHandshakeTranscript.approvalBytes(issuerOffer, memberOffer))
        for (wrongDomain in listOf(oldBootstrap, admission.signature)) {
            assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
                verify(context, member, issuer, wrongDomain, issuerKey))
        }
    }

    @Test
    fun oldConfirmationDoesNotVerifyWithChangedNonceAnchorOrProof() {
        val signature = sign(issuerKey, context.approvalBytes(issuer))
        val nonceChanged = context(issuer = ProtocolHandshakeParticipant(issuer, other, caps))
        val rootChanged = context(root = GroupTrustAnchor(other, issuer),
            supplied = admission.copy(claim = claim.copy(groupId = other)))
        val founderChanged = context(root = GroupTrustAnchor(group, other))
        val proofChanged = context(supplied = admission.copy(signature = sign(memberKey, GroupAdmissionCodec.signedBytes(claim))))
        for (changed in listOf(nonceChanged, rootChanged, founderChanged, proofChanged)) {
            assertEquals(GroupAdmissionConfirmationResult.InvalidSignature,
                verify(changed, member, issuer, signature, issuerKey))
        }
    }

    private fun context(
        issuer: ProtocolHandshakeParticipant = issuerOffer,
        root: GroupTrustAnchor = anchor,
        supplied: SignedGroupAdmission = admission,
    ) = GroupAdmissionConfirmationContext(issuer, memberOffer, root, GroupAdmissionProof(root, listOf(supplied)))

    private fun verify(context: GroupAdmissionConfirmationContext, local: String, remote: String,
        signature: String, key: KeyPair) = GroupAdmissionConfirmationVerification.verifyRemote(
        context, local, remote, remote, local, signature,
    ) { bytes, encoded ->
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.public)
            update(bytes)
            verify(Base64.getDecoder().decode(encoded))
        }
    }

    private fun sign(key: KeyPair, bytes: ByteArray): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(bytes)
            sign()
        },
    )

    private fun verifySignature(key: KeyPair, bytes: ByteArray, signature: String) =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.public)
            update(bytes)
            verify(Base64.getDecoder().decode(signature))
        }

    private fun keyPair() = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }
}
