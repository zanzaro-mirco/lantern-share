package lantern.connectivity

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionCertificate
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionCodec
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionEvidenceCodec
import lantern.protocol.GroupAdmissionProof
import lantern.protocol.SignedGroupAdmission
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class GroupAdmissionEvidenceCertificatesTest {
    @Test
    fun realCertificatesAndSignedDelegationSurviveSharedCodecAndOsDecoder() {
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        val proof = GroupAdmissionProof(anchor, listOf(admission(anchor, founder, issuer), admission(anchor, issuer, member)))
        val evidence = GroupAdmissionEvidence(proof, listOf(certificate(issuer), certificate(founder)))
        val received = GroupAdmissionEvidenceCodec.decode(GroupAdmissionEvidenceCodec.encode(evidence))
        val decoded = GroupAdmissionEvidenceCertificates.decode(received)
        assertEquals(setOf(founder.id, issuer.id), decoded.keys)
        assertContentEquals(founder.certificate.encoded, decoded.getValue(founder.id).encoded)
        assertContentEquals(issuer.certificate.encoded, decoded.getValue(issuer.id).encoded)
        val verifier = GroupAdmissionCertificateVerifier(decoded::get)
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(received.proof, anchor, member.id, verifier::verify))
        assertEquals(GroupAdmissionChainResult.AnchorMismatch,
            GroupAdmissionChainVerification.verify(received.proof, GroupTrustAnchor(randomNonce(), founder.id), member.id) { _, _, _ ->
                error("Received anchor is not local trust")
            })
        val altered = GroupAdmissionProof(anchor, listOf(proof.admissions.first(),
            SignedGroupAdmission(proof.admissions.last().claim, founder.sign(byteArrayOf(1)))))
        assertEquals(GroupAdmissionChainResult.InvalidSignature(1),
            GroupAdmissionChainVerification.verify(altered, anchor, member.id, verifier::verify))
    }

    @Test
    fun advertisedPinCannotSubstituteAnotherCertificate() {
        val founder = createDesktopIdentity().identity()
        val replacement = createDesktopIdentity().identity()
        assertInvalid(evidence(founder, replacement.certificate.encoded))
    }

    @Test
    fun samePublicKeyWithDifferentCertificateStillHasADifferentIdentity() {
        val keys = keyPair()
        val original = identity(keys)
        val replacement = identity(keys)
        assertContentEquals(original.certificate.publicKey.encoded, replacement.certificate.publicKey.encoded)
        assertFalse(original.id == replacement.id)
        assertInvalid(evidence(original, replacement.certificate.encoded))
    }

    @Test
    fun parsingTheExactPinDoesNotBypassValidityCurveOrCertificateSelfSignature() {
        val now = System.currentTimeMillis()
        val keys = keyPair()
        val invalid = listOf(
            identity(keys, now - 120_000, now - 60_000),
            identity(keys, now + 60_000, now + 120_000),
            identity(keyPair("secp384r1")),
            identity(keys, signer = keyPair()),
        )
        for (founder in invalid) {
            val received = evidence(founder, founder.certificate.encoded)
            val decoded = GroupAdmissionEvidenceCertificates.decode(received)
            assertEquals(setOf(founder.id), decoded.keys) // Parsing is explicitly NOT verification.
            val verifier = GroupAdmissionCertificateVerifier(decoded::get)
            assertEquals(GroupAdmissionChainResult.InvalidSignature(0),
                GroupAdmissionChainVerification.verify(received.proof, received.proof.anchor,
                    received.proof.admissions.last().claim.memberId, verifier::verify))
        }
    }

    @Test
    fun invalidDerTrailingBytesAndMultipleCertificatesAreRejectedWithoutPeerDiagnostics() {
        val founder = createDesktopIdentity().identity()
        val der = founder.certificate.encoded
        for (invalid in listOf(byteArrayOf(0), der.copyOf(der.size - 1), der + byteArrayOf(0), der + der)) {
            assertInvalid(evidence(founder, invalid))
        }
    }

    @Test
    fun pemIsNotAnAlternativeEncodingOfThePinnedDerCertificate() {
        val founder = createDesktopIdentity().identity()
        val pem = "-----BEGIN CERTIFICATE-----\n" +
            Base64.getEncoder().encodeToString(founder.certificate.encoded) + "\n-----END CERTIFICATE-----\n"
        assertInvalid(evidence(founder, pem.encodeToByteArray()))
    }

    @Test
    fun failureInLaterCertificateDoesNotReturnAPartiallyDecodedMap() {
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        val proof = GroupAdmissionProof(anchor, listOf(admission(anchor, founder, issuer), admission(anchor, issuer, member)))
        assertInvalid(GroupAdmissionEvidence(proof, listOf(certificate(founder), GroupAdmissionCertificate(issuer.id, "AA=="))))
    }

    @Test
    fun commonCertificateBoundsAndCanonicalBitsAgreeWithJdkBase64() {
        val pin = "a".repeat(64)
        for (size in 1..GroupAdmissionCertificate.MAX_DER_BYTES) {
            val bytes = ByteArray(size) { index -> ((index * 31 + size) and 255).toByte() }
            val encoded = Base64.getEncoder().encodeToString(bytes)
            assertEquals(encoded, GroupAdmissionCertificate(pin, encoded).der)
            assertContentEquals(bytes, Base64.getDecoder().decode(encoded))
        }
        assertFailsWith<IllegalArgumentException> {
            GroupAdmissionCertificate(pin, Base64.getEncoder().encodeToString(ByteArray(GroupAdmissionCertificate.MAX_DER_BYTES + 1)))
        }
        for ((canonical, alias) in listOf("/w==" to "/x==", "//8=" to "//9=")) {
            assertContentEquals(Base64.getDecoder().decode(canonical), Base64.getDecoder().decode(alias))
            assertFailsWith<IllegalArgumentException> { GroupAdmissionCertificate(pin, alias) }
        }
    }

    private fun certificate(identity: Identity) = GroupAdmissionCertificate(identity.id,
        Base64.getEncoder().encodeToString(identity.certificate.encoded))

    private fun evidence(founder: Identity, bytes: ByteArray): GroupAdmissionEvidence {
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        return GroupAdmissionEvidence(GroupAdmissionProof(anchor, listOf(admission(anchor, founder, member))),
            listOf(GroupAdmissionCertificate(founder.id, Base64.getEncoder().encodeToString(bytes))))
    }

    private fun admission(anchor: GroupTrustAnchor, issuer: Identity, member: Identity): SignedGroupAdmission {
        val claim = GroupAdmissionClaim(anchor.groupId, issuer.id, member.id)
        return SignedGroupAdmission(claim, issuer.sign(GroupAdmissionCodec.signedBytes(claim)))
    }

    private fun assertInvalid(evidence: GroupAdmissionEvidence) {
        val failure = assertFailsWith<InvalidGroupAdmissionCertificateException> {
            GroupAdmissionEvidenceCertificates.decode(evidence)
        }
        assertEquals("Invalid group admission certificate", failure.message)
        assertNull(failure.cause)
        assertEquals(0, failure.suppressed.size)
    }

    private fun keyPair(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(curve))
        generateKeyPair()
    }

    private fun identity(
        keys: KeyPair,
        notBefore: Long = System.currentTimeMillis() - 60_000,
        notAfter: Long = System.currentTimeMillis() + 120_000,
        signer: KeyPair = keys,
    ): Identity {
        val name = X500Name("CN=Lantern evidence test")
        val certificate = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(name, BigInteger(128, SecureRandom()), Date(notBefore), Date(notAfter), name, keys.public)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)),
        )
        return Identity(certificate, keys.private)
    }
}
