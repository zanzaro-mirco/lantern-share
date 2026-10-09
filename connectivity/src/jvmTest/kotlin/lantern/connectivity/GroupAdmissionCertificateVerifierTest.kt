package lantern.connectivity

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionCodec
import lantern.protocol.SignedGroupAdmission
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.ProviderException
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class GroupAdmissionCertificateVerifierTest {
    @Test
    fun verifiesDelegatedProofWithActualCertificatePins() {
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        val certificates = mapOf(founder.id to founder.certificate, issuer.id to issuer.certificate)
        val verifier = GroupAdmissionCertificateVerifier(certificates::get)
        val path = listOf(admission(anchor, founder, issuer), admission(anchor, issuer, member))
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(anchor, member.id, path, verifier::verify))
        val incomplete = GroupAdmissionCertificateVerifier { certificates[it].takeIf { it != issuer.certificate } }
        assertEquals(GroupAdmissionChainResult.InvalidSignature(1),
            GroupAdmissionChainVerification.verify(anchor, member.id, path, incomplete::verify))
    }

    @Test
    fun missingOrSubstitutedCertificateCannotVerifyEvenWithTheSamePublicKey() {
        val keys = keyPair()
        val original = certificate(keys)
        val replacement = certificate(keys)
        val pin = digest(original.certificate.encoded)
        val bytes = "admission".encodeToByteArray()
        val signature = original.identity().sign(bytes)
        assertFalse(GroupAdmissionCertificateVerifier { null }.verify(pin, bytes, signature))
        assertFalse(GroupAdmissionCertificateVerifier { replacement.certificate }.verify(pin, bytes, signature))
        assertTrue(GroupAdmissionCertificateVerifier { original.certificate }.verify(pin, bytes, signature))
    }

    @Test
    fun expiredAndFutureCertificatesRefuseAtTheirExactPins() {
        val now = System.currentTimeMillis()
        for (material in listOf(
            certificate(keyPair(), now - 120_000, now - 60_000),
            certificate(keyPair(), now + 60_000, now + 120_000),
        )) {
            val identity = Identity(material.certificate, material.privateKey)
            val bytes = byteArrayOf(1)
            assertFalse(GroupAdmissionCertificateVerifier { material.certificate }
                .verify(identity.id, bytes, identity.sign(bytes)))
        }
    }

    @Test
    fun wrongCurveAndCertificateSelfSignatureAreRejected() {
        val keys = keyPair()
        for (material in listOf(certificate(keyPair("secp384r1")), certificate(keys, signer = keyPair()))) {
            val identity = Identity(material.certificate, material.privateKey)
            val bytes = byteArrayOf(2)
            assertFalse(GroupAdmissionCertificateVerifier { material.certificate }
                .verify(identity.id, bytes, identity.sign(bytes)))
        }
    }

    @Test
    fun modifiedBytesWrongKeyAndMalformedSignaturesRefuse() {
        val identity = createDesktopIdentity().identity()
        val other = createDesktopIdentity().identity()
        val verifier = GroupAdmissionCertificateVerifier { identity.certificate }
        val bytes = byteArrayOf(1, 2)
        val signature = identity.sign(bytes)
        assertFalse(verifier.verify(identity.id, byteArrayOf(1, 3), signature))
        assertFalse(verifier.verify(identity.id, bytes, other.sign(bytes)))
        for (invalid in listOf("AQ==", "AR==", "%%%%", "", "A".repeat(260), signature.trimEnd('='))) {
            // DER lengths can occasionally need no Base64 padding; test that case separately.
            if (invalid != signature) assertFalse(verifier.verify(identity.id, bytes, invalid))
        }
    }

    @Test
    fun resolverFailuresAndCancellationPropagateUnchanged() {
        val identity = createDesktopIdentity().identity()
        val bytes = byteArrayOf(3)
        val signature = identity.sign(bytes)
        val failure = ProviderException("OS unavailable")
        assertSame(failure, assertFailsWith<ProviderException> {
            GroupAdmissionCertificateVerifier { throw failure }.verify(identity.id, bytes, signature)
        })
        val cancellation = CancellationException("cancelled")
        assertSame(cancellation, assertFailsWith<CancellationException> {
            GroupAdmissionCertificateVerifier { throw cancellation }.verify(identity.id, bytes, signature)
        })
    }

    @Test
    fun invalidExpectedPinNeverReachesResolverAndCertificatesAreNotCached() {
        val identity = createDesktopIdentity().identity()
        val bytes = byteArrayOf(4)
        val signature = identity.sign(bytes)
        var calls = 0
        val verifier = GroupAdmissionCertificateVerifier { if (++calls == 1) identity.certificate else null }
        assertFailsWith<IllegalArgumentException> { verifier.verify("alias", bytes, signature) }
        assertEquals(0, calls)
        assertTrue(verifier.verify(identity.id, bytes, signature))
        assertFalse(verifier.verify(identity.id, bytes, signature))
        assertEquals(2, calls)
    }

    private fun admission(anchor: GroupTrustAnchor, issuer: Identity, member: Identity): SignedGroupAdmission {
        val claim = GroupAdmissionClaim(anchor.groupId, issuer.id, member.id)
        return SignedGroupAdmission(claim, issuer.sign(GroupAdmissionCodec.signedBytes(claim)))
    }

    private fun keyPair(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec(curve))
        generateKeyPair()
    }

    private fun certificate(
        keys: KeyPair,
        notBefore: Long = System.currentTimeMillis() - 60_000,
        notAfter: Long = System.currentTimeMillis() + 120_000,
        signer: KeyPair = keys,
    ): DesktopIdentityMaterial {
        val name = X500Name("CN=Lantern test")
        val builder = JcaX509v3CertificateBuilder(name, BigInteger(128, java.security.SecureRandom()),
            Date(notBefore), Date(notAfter), name, keys.public)
        return DesktopIdentityMaterial(keys.private, JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)),
        ))
    }
}
