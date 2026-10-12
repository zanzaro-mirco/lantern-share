package lantern.connectivity

import lantern.domain.GroupTrustAnchor
import lantern.domain.LocalGroupRepository
import lantern.persistence.openDesktopRepository
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionChainVerification
import lantern.protocol.GroupAdmissionProofCodec
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class FounderGroupAdmissionTest {
    @Test
    fun reopenedFoundationProducesVerifiableEvidenceWithoutAuthorizingPeer() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), identity.id)
        openDesktopRepository(path).use { repository ->
            repository.rename("Founder")
            assertTrue(repository.foundLocalGroup(anchor, identity.id))
        }
        val proof = openDesktopRepository(path).use { repository ->
            prepareFounderGroupAdmission(identity, repository, member.id).also {
                assertEquals(anchor, repository.localGroup())
                assertEquals("Founder", repository.name())
                assertTrue(repository.trusted().isEmpty())
                assertTrue(repository.history().isEmpty())
            }
        }
        val verifier = GroupAdmissionCertificateVerifier { id -> identity.certificate.takeIf { id == identity.id } }
        val decoded = GroupAdmissionProofCodec.decode(GroupAdmissionProofCodec.encode(proof))
        assertEquals(GroupAdmissionChainResult.VerifiedChain,
            GroupAdmissionChainVerification.verify(decoded, anchor, member.id, verifier::verify))
        openDesktopRepository(path).use { repository ->
            assertEquals(anchor, repository.localGroup())
            assertTrue(repository.trusted().isEmpty())
        }
    }

    @Test
    fun emptyDatabaseDoesNotCreateAFoundation() = withDatabase { path ->
        openDesktopRepository(path).use { repository ->
            assertFailsWith<IllegalArgumentException> {
                prepareFounderGroupAdmission(createDesktopIdentity().identity(), repository, "b".repeat(64))
            }
            assertNull(repository.localGroup())
            assertTrue(repository.trusted().isEmpty())
        }
    }

    @Test
    fun foreignFounderInvalidMemberAndSelfAdmissionLeaveStoredDataUnchanged() = withDatabase { path ->
        val identity = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), identity.id)
        openDesktopRepository(path).use { repository ->
            repository.foundLocalGroup(anchor, identity.id)
            repository.trust("b".repeat(64), "existing PoC trust")
            val trusted = repository.trusted()
            assertFailsWith<IllegalArgumentException> {
                prepareFounderGroupAdmission(createDesktopIdentity().identity(), repository, "c".repeat(64))
            }
            for (member in listOf(identity.id, "bad", "B".repeat(64))) {
                assertFailsWith<IllegalArgumentException> { prepareFounderGroupAdmission(identity, repository, member) }
            }
            assertEquals(anchor, repository.localGroup())
            assertEquals(trusted, repository.trusted())
        }
    }

    @Test
    fun signingWithKeyThatDoesNotMatchSavedIdentityNeverReturnsEvidence() = withDatabase { path ->
        val material = createDesktopIdentity()
        val otherKey = createDesktopIdentity().privateKey
        val broken = Identity(material.certificate, otherKey)
        openDesktopRepository(path).use { repository ->
            val anchor = GroupTrustAnchor(randomNonce(), broken.id)
            repository.foundLocalGroup(anchor, broken.id)
            assertFailsWith<IllegalStateException> { prepareFounderGroupAdmission(broken, repository, "b".repeat(64)) }
            assertEquals(anchor, repository.localGroup())
            assertTrue(repository.trusted().isEmpty())
        }
    }

    @Test
    fun storageFailurePropagatesAndNoWriteIsAttempted() {
        val identity = createDesktopIdentity().identity()
        val failure = IllegalStateException("read unavailable")
        val repository = readOnlyRepository { throw failure }
        val thrown = assertFailsWith<IllegalStateException> {
            prepareFounderGroupAdmission(identity, repository, "b".repeat(64))
        }
        assertSame(failure, thrown)
    }

    @Test
    fun changedOrMissingRootAtFinalReadDoesNotReleaseEvidence() {
        val identity = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), identity.id)
        for (changed in listOf(null, GroupTrustAnchor(randomNonce(), identity.id))) {
            var reads = 0
            val repository = readOnlyRepository { if (++reads == 1) anchor else changed }
            assertFailsWith<IllegalStateException> { prepareFounderGroupAdmission(identity, repository, "b".repeat(64)) }
            assertEquals(2, reads)
        }
    }

    @Test
    fun finalReadFailureDoesNotReturnOrRetrySignedEvidence() {
        val identity = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), identity.id)
        val failure = IllegalStateException("final read unavailable")
        var reads = 0
        val repository = readOnlyRepository { if (++reads == 1) anchor else throw failure }
        val thrown = assertFailsWith<IllegalStateException> {
            prepareFounderGroupAdmission(identity, repository, "b".repeat(64))
        }
        assertSame(failure, thrown)
        assertEquals(2, reads)
    }

    private fun readOnlyRepository(read: () -> GroupTrustAnchor?) = object : LocalGroupRepository {
        override fun localGroup(): GroupTrustAnchor? = read()
        override fun foundLocalGroup(anchor: GroupTrustAnchor, currentIdentityId: String): Boolean =
            error("Issuing evidence must not write local membership")
    }

    private fun withDatabase(test: (Path) -> Unit) {
        val directory = Files.createTempDirectory("lantern-founder-admission-test-")
        try {
            test(directory.resolve("lantern.db"))
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
