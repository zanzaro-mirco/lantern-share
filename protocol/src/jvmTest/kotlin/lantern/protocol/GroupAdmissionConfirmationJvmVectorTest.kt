package lantern.protocol

import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import lantern.domain.GroupTrustAnchor
import lantern.domain.PendingGroupAdoption

/**
 * Verify the actual public Apple test fixture with shared Kotlin and real JCA crypto.
 * Reading test data from iosApp/Tests is deliberate; no Swift implementation is imported.
 * This is not Apple execution, TLS, a new app identity or durable group membership.
 */
class GroupAdmissionConfirmationJvmVectorTest {
    private val vectors = loadVectors()
    private val issuer = vectors.getValue("issuer")
    private val member = vectors.getValue("member")
    private val anchor = GroupTrustAnchor(vectors.getValue("group"), issuer)
    private val evidence = GroupAdmissionEvidenceCodec.decode(decode("evidence"))
    private val alternative = GroupAdmissionEvidenceCodec.decode(decode("alternativeEvidence"))
    private val certificates = mapOf(
        issuer to certificate("issuerDer", issuer), member to certificate("memberDer", member),
    )
    private val caps = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))

    @Test
    fun certificatesAndBothValidProofsMatchTheirExactPublicPins() {
        assertEquals(listOf(issuer), evidence.certificates.map { it.identity })
        assertContentEquals(decode("issuerDer"), Base64.getDecoder().decode(evidence.certificates.single().der))
        assertEquals(anchor, evidence.proof.anchor)
        assertEquals(evidence.certificates, alternative.certificates)
        assertNotEquals(evidence.proof.admissions.single().signature, alternative.proof.admissions.single().signature)
        for (supplied in listOf(evidence, alternative)) {
            assertEquals(GroupAdmissionChainResult.VerifiedChain,
                GroupAdmissionChainVerification.verify(supplied.proof, anchor, member, ::verify))
        }
    }

    @Test
    fun canonicalHashesAndDirectionalFramesAreFixedAcrossJcaAndAppleFixtures() {
        val context = context()
        assertEquals(vectors.getValue("comparisonHash"), hash(context.comparisonBytes()))
        for ((id, name) in listOf(issuer to "issuer", member to "member")) {
            val bytes = context.approvalBytes(id)
            val signature = vectors.getValue("${name}Signature")
            assertEquals(vectors.getValue("${name}ApprovalHash"), hash(bytes))
            assertTrue(verify(id, bytes, signature))
            val recipient = if (id == issuer) member else issuer
            assertContentEquals(decode("${name}Frame"), GroupAdmissionConfirmationFrameDecoder.encode(
                GroupAdmissionConfirmation(id, recipient, signature),
            ))
        }
        assertFalse(verify(issuer, context.approvalBytes(issuer), vectors.getValue("wrongIssuerSignature")))
        assertTrue(verify(member, context.approvalBytes(issuer), vectors.getValue("wrongIssuerSignature")))
    }

    @Test
    fun appleJournalFixtureUsesTheSameOriginalOffersAndHistoricalDirectionalSignatures() {
        val journal = GroupRootAdoptionJournal(evidence,
            ProtocolHandshakeParticipant(member, "2".repeat(64), caps),
            ProtocolHandshakeParticipant(issuer, "1".repeat(64), caps),
            GroupAdmissionCertificate(member, vectors.getValue("memberDer")),
            GroupAdmissionConfirmation(member, issuer, vectors.getValue("memberSignature")),
            GroupAdmissionConfirmation(issuer, member, vectors.getValue("issuerSignature")))
        val record = PendingGroupAdoption("e".repeat(64), member, issuer, anchor, GroupRootAdoptionJournalCodec.encode(journal))
        assertEquals(GroupRootAdoptionJournalInspectionResult.HistoricalSignaturesValid,
            GroupRootAdoptionJournalInspection.inspect(record, member) { supplied, bytes, signature ->
                assertContentEquals(certificates.getValue(supplied.identity).encoded, Base64.getDecoder().decode(supplied.der))
                verify(supplied.identity, bytes, signature)
            })
        val alternate = GroupRootAdoptionJournal(alternative, journal.localOffer, journal.remoteOffer,
            journal.memberCertificate, journal.localConfirmation, journal.remoteConfirmation)
        assertEquals(GroupRootAdoptionJournalInspectionResult.InvalidLocalConfirmation,
            GroupRootAdoptionJournalInspection.inspect(PendingGroupAdoption(record.attemptId, member, issuer, anchor,
                GroupRootAdoptionJournalCodec.encode(alternate)), member) { supplied, bytes, signature ->
                verify(supplied.identity, bytes, signature)
            })
    }

    @Test
    fun actualJvmSignaturesNeedBothLocalWriteAcknowledgementsAndRemainRevocable() {
        val issuerBridge = bridge(local = issuer)
        val memberBridge = bridge(local = member)
        val issuerWrite = pendingWrite(issuerBridge, "issuerSignature")
        val memberWrite = pendingWrite(memberBridge, "memberSignature")
        assertTrue(issuerBridge.accept(decode("memberFrame")))
        assertTrue(memberBridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(true)), issuerBridge.state())
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(true)), memberBridge.state())
        assertTrue(issuerBridge.sent(issuerWrite))
        assertTrue(memberBridge.sent(memberWrite))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), issuerBridge.state())
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), memberBridge.state())
        memberBridge.finish()
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.TransportClosed)), memberBridge.state())
        issuerBridge.block()
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.Blocked)), issuerBridge.state())
    }

    @Test
    fun freshNonceOrAnotherValidProofCannotReuseOldDirectionalSignature() {
        for (changed in listOf(context(memberNonce = "3"), context(proof = alternative.proof))) {
            assertNotEquals(hash(context().comparisonBytes()), hash(changed.comparisonBytes()))
            val bridge = bridge(context = changed)
            assertTrue(bridge.prepare())
            assertFalse(bridge.accept(decode("issuerFrame")))
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
                GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.InvalidSignature))), bridge.state())
            assertNull(bridge.comparison())
        }
    }

    @Test
    fun wrongKeyAndReflectionFailWithoutLocalOrRemoteAuthorization() {
        val wrongKey = bridge()
        assertTrue(wrongKey.prepare())
        assertFalse(wrongKey.accept(GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(
            issuer, member, vectors.getValue("wrongIssuerSignature"),
        ))))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.InvalidSignature))), wrongKey.state())
        var remoteCalls = 0
        val reflected = bridge(remoteVerifier = { _, _ ->
            remoteCalls++
            error("Reflection must fail before crypto")
        })
        assertTrue(reflected.prepare())
        assertFalse(reflected.accept(GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(
            member, issuer, vectors.getValue("issuerSignature"),
        ))))
        assertEquals(0, remoteCalls)
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.AddressMismatch))), reflected.state())
    }

    @Test
    fun validBootstrapApprovalSignatureIsNotAGroupConfirmation() {
        val signature = vectors.getValue("bootstrapSignature")
        val issuerOffer = ProtocolHandshakeParticipant(issuer, "1".repeat(64), caps)
        val memberOffer = ProtocolHandshakeParticipant(member, "2".repeat(64), caps)
        assertTrue(verify(issuer, ProtocolHandshakeTranscript.approvalBytes(issuerOffer, memberOffer), signature))
        assertFalse(verify(issuer, context().approvalBytes(issuer), signature))
        val bridge = bridge()
        assertTrue(bridge.prepare())
        assertFalse(bridge.accept(GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(
            issuer, member, signature,
        ))))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.InvalidSignature))), bridge.state())
        assertNull(bridge.comparison())
    }

    @Test
    fun equivalentJsonAndFeatureOrderingPreserveTheSignedCanonicalContext() {
        val decorated = " \n" + decode("evidence").decodeToString().replace(
            "\"version\"", "\"ver\\u0073ion\"",
        ).replace(",", ",\n") + " \n"
        val supplied = GroupAdmissionEvidenceCodec.decode(decorated.encodeToByteArray())
        val reorderedCaps = ProtocolCapabilities(1, linkedSetOf("receipts", "text"), setOf("text"))
        val normalized = GroupAdmissionConfirmationContext(
            ProtocolHandshakeParticipant(issuer, "1".repeat(64), reorderedCaps),
            ProtocolHandshakeParticipant(member, "2".repeat(64), reorderedCaps), anchor, supplied.proof,
        )
        assertEquals(vectors.getValue("comparisonHash"), hash(normalized.comparisonBytes()))
        assertTrue(verify(issuer, normalized.approvalBytes(issuer), vectors.getValue("issuerSignature")))
        val bridge = bridge(context = normalized)
        assertTrue(bridge.prepare())
        assertTrue(bridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.AwaitingConfirmation(true)), bridge.state())
        bridge.cancel()
    }

    @Test
    fun fragmentedRealConfirmationInvokesCryptoOnlyAfterTheCompleteFrame() {
        var calls = 0
        val bridge = bridge(remoteVerifier = { bytes, signature ->
            calls++
            verify(issuer, bytes, signature)
        })
        assertTrue(bridge.prepare())
        val frame = decode("issuerFrame")
        for ((index, byte) in frame.withIndex()) {
            assertTrue(bridge.accept(byteArrayOf(byte)))
            assertEquals(if (index == frame.lastIndex) 1 else 0, calls)
            assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.AwaitingConfirmation(
                index == frame.lastIndex)), bridge.state())
        }
        assertEquals(vectors.getValue("comparisonHash"), hash(assertNotNull(bridge.comparison()).bytes))
        bridge.cancel()
    }

    @Test
    fun duplicateCryptographicallyValidConfirmationRevokesConfirmed() {
        val bridge = bridge()
        val write = pendingWrite(bridge, "memberSignature")
        assertTrue(bridge.accept(decode("issuerFrame")))
        assertTrue(bridge.sent(write))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), bridge.state())
        assertFalse(bridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.UnexpectedConfirmation)), bridge.state())
        assertNull(bridge.comparison())
        assertFalse(bridge.sent(write))
    }

    @Test
    fun anotherCompatibleOfferStillChangesTheSignedCompleteTranscript() {
        val changedCaps = ProtocolCapabilities(1, setOf("text", "receipts", "files"), setOf("text"))
        val negotiated = ProtocolNegotiation.negotiate(caps, changedCaps)
        assertTrue(negotiated is ProtocolNegotiationResult.Compatible)
        assertEquals(setOf("text", "receipts"), negotiated.features)
        val changedContext = context(memberCapabilities = changedCaps)
        assertNotEquals(vectors.getValue("comparisonHash"), hash(changedContext.comparisonBytes()))
        val bridge = bridge(context = changedContext)
        assertTrue(bridge.prepare())
        assertFalse(bridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.InvalidRemoteConfirmation(GroupAdmissionConfirmationResult.InvalidSignature))), bridge.state())
    }

    @Test
    fun everyTruncatedRealFrameClosesWithoutCryptoAndCannotBeCompletedAfterEof() {
        val frame = decode("issuerFrame")
        for (length in 1 until frame.size) {
            var calls = 0
            val bridge = bridge(remoteVerifier = { _, _ ->
                calls++
                error("Incomplete confirmation must not reach crypto")
            })
            assertTrue(bridge.prepare())
            val comparison = assertNotNull(bridge.comparison())
            assertTrue(bridge.accept(frame.copyOf(length)))
            assertFailsWith<IllegalArgumentException>("Prefix length $length") { bridge.finish() }
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), bridge.state())
            assertEquals(0, calls)
            assertFalse(bridge.accept(frame.copyOfRange(length, frame.size)))
            assertNull(bridge.confirm(comparison))
            assertNull(bridge.comparison())
        }
    }

    @Test
    fun validFrameWithMalformedCoalescedTailCannotPublishPartialVerification() {
        val frame = decode("issuerFrame")
        // Invalid lengths and invalid UTF-8/JSON following a complete, valid signed frame.
        val tails = listOf(byteArrayOf(0, 0, 0, 0), byteArrayOf(0, 0, 0, 1, -1),
            byteArrayOf(0, 0, 0, 1, '{'.code.toByte()))
        for (tail in tails) {
            var calls = 0
            val bridge = bridge(remoteVerifier = { _, _ ->
                calls++
                error("A malformed chunk must not publish its valid prefix")
            })
            val write = pendingWrite(bridge, "memberSignature")
            assertFailsWith<IllegalArgumentException> { bridge.accept(frame + tail) }
            assertEquals(0, calls)
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), bridge.state())
            assertFalse(bridge.sent(write))
            assertFalse(bridge.writeFailed(write))
            assertNull(bridge.comparison())
        }
    }

    @Test
    fun eofAfterValidRemoteConfirmationInvalidatesPendingRealLocalSignature() {
        val bridge = bridge()
        assertTrue(bridge.prepare())
        val comparison = assertNotNull(bridge.comparison())
        val signing = assertNotNull(bridge.confirm(comparison))
        assertTrue(bridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Signing(true)), bridge.state())
        bridge.finish()
        val closed = GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(
            GroupAdmissionConfirmationFailure.TransportClosed))
        assertEquals(closed, bridge.state())
        assertNull(bridge.signed(signing, vectors.getValue("memberSignature")))
        assertFalse(bridge.signingFailed(signing))
        assertNull(bridge.confirm(comparison))
        assertFalse(bridge.accept(decode("issuerFrame")))
        assertEquals(closed, bridge.state())
    }

    @Test
    fun failedLocalWriteAfterValidRemoteSignatureCannotBeAcknowledgedLater() {
        val bridge = bridge()
        val write = pendingWrite(bridge, "memberSignature")
        assertTrue(bridge.accept(decode("issuerFrame")))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(true)), bridge.state())
        assertTrue(bridge.writeFailed(write))
        val closed = GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Transport)
        assertEquals(closed, bridge.state())
        assertFalse(bridge.sent(write))
        assertFalse(bridge.writeFailed(write))
        assertFalse(bridge.accept(decode("issuerFrame")))
        assertNull(bridge.comparison())
        assertEquals(closed, bridge.state())
    }

    @Test
    fun malformedTailAfterConfirmedRevokesTheAttemptAndPreservesItsFirstFailure() {
        val bridge = bridge()
        val write = pendingWrite(bridge, "memberSignature")
        assertTrue(bridge.accept(decode("issuerFrame")))
        assertTrue(bridge.sent(write))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), bridge.state())
        assertFailsWith<IllegalArgumentException> { bridge.accept(byteArrayOf(0, 0, 0, 0)) }
        val closed = GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame)
        assertEquals(closed, bridge.state())
        bridge.finish()
        bridge.cancel()
        bridge.block()
        bridge.leaveGroup()
        bridge.transportFailed()
        assertFalse(bridge.sent(write))
        assertFalse(bridge.accept(decode("issuerFrame")))
        assertNull(bridge.comparison())
        assertEquals(closed, bridge.state())
    }

    @Test
    fun identicalPublicTranscriptStillCannotTransferAnotherInstancesCallbackTickets() {
        // Identical nonces are deliberate test data; production reconnects use fresh nonces.
        val first = bridge()
        val replacement = bridge()
        assertTrue(first.prepare())
        assertTrue(replacement.prepare())
        val oldComparison = assertNotNull(first.comparison())
        val comparison = assertNotNull(replacement.comparison())
        assertContentEquals(oldComparison.bytes, comparison.bytes)
        assertNull(replacement.confirm(oldComparison))
        val oldSigning = assertNotNull(first.confirm(oldComparison))
        val signing = assertNotNull(replacement.confirm(comparison))
        assertNull(replacement.signed(oldSigning, vectors.getValue("memberSignature")))
        assertFalse(replacement.signingFailed(oldSigning))
        val oldWrite = assertNotNull(first.signed(oldSigning, vectors.getValue("memberSignature")))
        val write = assertNotNull(replacement.signed(signing, vectors.getValue("memberSignature")))
        assertContentEquals(oldWrite.bytes, write.bytes)
        assertFalse(replacement.sent(oldWrite))
        assertFalse(replacement.writeFailed(oldWrite))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Sending(false)), replacement.state())
        assertTrue(replacement.accept(decode("issuerFrame")))
        assertTrue(replacement.sent(write))
        assertEquals(GroupAdmissionBridgeState.Active(GroupAdmissionConfirmationState.Confirmed), replacement.state())
        first.cancel()
        replacement.cancel()
    }

    private fun context(
        memberNonce: String = "2", proof: GroupAdmissionProof = evidence.proof,
        memberCapabilities: ProtocolCapabilities = caps,
    ) = GroupAdmissionConfirmationContext(
        ProtocolHandshakeParticipant(issuer, "1".repeat(64), caps),
        ProtocolHandshakeParticipant(member, memberNonce.repeat(64), memberCapabilities), anchor, proof,
    )

    private fun bridge(
        local: String = member, context: GroupAdmissionConfirmationContext = context(),
        remoteVerifier: ((ByteArray, String) -> Boolean)? = null,
    ): GroupAdmissionConfirmationBridge {
        val peer = if (local == issuer) member else issuer
        return GroupAdmissionConfirmationBridge(context, local, local, peer, peer, 0, { 17 }, ::verify,
            remoteVerifier ?: { bytes, signature -> verify(peer, bytes, signature) })
    }

    private fun pendingWrite(bridge: GroupAdmissionConfirmationBridge, signatureName: String): GroupAdmissionBridgeWrite {
        assertTrue(bridge.prepare())
        val sign = assertNotNull(bridge.confirm(assertNotNull(bridge.comparison())))
        return assertNotNull(bridge.signed(sign, vectors.getValue(signatureName)))
    }

    private fun verify(id: String, bytes: ByteArray, signature: String): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(certificates.getValue(id).publicKey)
            update(bytes)
            verify(Base64.getDecoder().decode(signature))
        }

    private fun certificate(name: String, expectedID: String): X509Certificate {
        val der = decode(name)
        assertEquals(expectedID, hash(der))
        val input = ByteArrayInputStream(der)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        assertEquals(0, input.available())
        assertContentEquals(der, certificate.encoded)
        certificate.verify(certificate.publicKey)
        certificate.checkValidity(Date.from(Instant.parse("2026-10-11T00:00:00Z")))
        assertEquals("1.2.840.10045.4.3.2", certificate.sigAlgOID)
        val actualCurve = (certificate.publicKey as ECPublicKey).params
        val expectedCurve = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        assertEquals(expectedCurve.curve, actualCurve.curve)
        assertEquals(expectedCurve.generator, actualCurve.generator)
        assertEquals(expectedCurve.order, actualCurve.order)
        assertEquals(expectedCurve.cofactor, actualCurve.cofactor)
        return certificate
    }

    private fun decode(name: String): ByteArray = Base64.getDecoder().decode(vectors.getValue(name))
    private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun loadVectors(): Map<String, String> {
        // Gradle executes this module's tests from protocol/. Only public test constants are read.
        val source = Files.readString(Path.of("..", "iosApp", "Tests", "JvmGroupConfirmationVectors.swift"))
        val fields = Regex("static let (\\w+) = \"([A-Za-z0-9+/=]+)\"").findAll(source)
            .associate { it.groupValues[1] to it.groupValues[2] }
        assertEquals(setOf("issuer", "member", "group", "issuerDer", "memberDer", "evidence", "alternativeEvidence",
            "comparisonHash", "issuerApprovalHash", "memberApprovalHash", "issuerSignature", "memberSignature",
            "wrongIssuerSignature", "bootstrapSignature", "issuerFrame", "memberFrame"), fields.keys)
        return fields
    }
}
