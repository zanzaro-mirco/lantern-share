package lantern.connectivity

import lantern.protocol.GroupSessionJoin
import lantern.protocol.GroupSessionRoster
import lantern.protocol.GroupSessionRosterCodec
import lantern.protocol.GroupRosterTextCodec
import kotlin.test.assertContentEquals

import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeApproval
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.ProtocolHandshakeComparison
import lantern.protocol.ProtocolHandshakeFailure
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeFrameCodec
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.ProtocolHandshakeState
import lantern.protocol.ProtocolNegotiationResult
import lantern.protocol.GroupMembershipEvidence
import lantern.protocol.GroupMembershipEvidenceCodec
import lantern.domain.GroupTrustAnchor
import lantern.domain.SessionCandidate
import lantern.protocol.GroupSessionOffer
import lantern.protocol.GroupSessionOfferCodec
import lantern.protocol.GroupTextTransferCodec
import lantern.protocol.GroupTextTransferContext
import lantern.protocol.GroupTextCodec
import lantern.domain.GroupTextContent
import lantern.domain.SignedGroupText
import lantern.protocol.FounderGroupAdmissionDraft
import lantern.protocol.GroupAdmissionEvidence
import lantern.protocol.GroupAdmissionCertificate
import java.util.Base64

/** Real pinned mutual TLS and JCA signatures; only UI confirmation and selected clocks are simulated. */
class HandshakeV1ConnectionTest {
    private val capabilities = ProtocolCapabilities(1, setOf("text", "receipts"), setOf("text"))

    @Test
    fun ownerRequiresOneHelloWriteAndExplicitConfirmationOnBothSides() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    assertEquals(HandshakeV1ConnectionState.AwaitingStart, left.state)
                    assertFalse(left.readNext())
                    assertFalse(sockets.scheduler.isShutdown)
                    assertNull(left.comparison())
                    exchangeHellos(left, right)
                    val leftCode = assertNotNull(left.comparison())
                    val rightCode = assertNotNull(right.comparison())
                    assertEquals(digest(leftCode.bytes), digest(rightCode.bytes))
                    // Test-only explicit UI confirmation, never inferred from receiving remote proof.
                    assertTrue(left.confirm(leftCode))
                    assertFalse(left.confirm(leftCode))
                    assertTrue(right.readNext())
                    assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(true)), right.state)
                    assertEquals(active(ProtocolHandshakeState.AwaitingRemoteApproval), left.state)
                    assertTrue(right.confirm(rightCode))
                    assertReady(right)
                    assertTrue(left.readNext())
                    assertReady(left)
                    left.close()
                    assertHandshakeClosed(left, ProtocolHandshakeFailure.Cancelled)
                    assertTrue(sockets.client.isClosed)
                    assertFalse(left.confirm(leftCode))
                    assertFalse(left.start())
                    assertFalse(left.readNext())
                }
            }
            assertTrue(sockets.server.isClosed)
        }
    }

    @Test
    fun adoptionPreparesAbortPolicyBeforeEitherPeerShutsDown() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    // Assert policy before HELLO/reader/close can configure it too late.
                    assertEquals(0, sockets.client.soLinger)
                    assertEquals(0, sockets.server.soLinger)
                    exchangeHellos(left, right)
                    sockets.client.shutdownOutput()
                    left.close()
                    right.close()
                    assertTrue(sockets.client.isClosed)
                    assertTrue(sockets.server.isClosed)
                    assertHandshakeClosed(left, ProtocolHandshakeFailure.Cancelled)
                    assertHandshakeClosed(right, ProtocolHandshakeFailure.Cancelled)
                }
            }
        }
    }

    @Test
    fun unavailableAbortPolicyFailsAdoptionAndClosesTransferredSocket() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val failure = java.net.SocketException("test-only unavailable abort policy")
            val transport = LingerFailureSocket(sockets.client, failure)
            assertSame(failure, assertFailsWith<java.net.SocketException> {
                HandshakeV1Connection.adopt(transport, client, capabilities, server.id, sockets.selectedAt, sockets.scheduler)
            })
            assertEquals(1, transport.lingerAttempts)
            assertTrue(sockets.client.isClosed)
            assertFalse(sockets.scheduler.isShutdown)
        }
    }

    @Test
    fun initialHelloIsWrittenOnlyOnceAndNotOnReadBeforeStart() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertFalse(owner.readNext())
                assertTrue(owner.start())
                assertFalse(owner.start())
                val remote = HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream)
                assertIs<ProtocolHandshakeFrame.Hello>(remote.read())
                sockets.server.soTimeout = 100
                assertFailsWith<SocketTimeoutException> { remote.read() }
                assertEquals(active(ProtocolHandshakeState.AwaitingHello), owner.state)
            }
        }
    }

    @Test
    fun selectedPinMismatchClosesBeforeHelloAndCannotBeStarted() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val unexpected = foreignId(client, server)
            val owner = HandshakeV1Connection.adopt(sockets.client, client, capabilities, unexpected, sockets.selectedAt, sockets.scheduler)
            assertHandshakeClosed(owner, ProtocolHandshakeFailure.IdentityMismatch)
            assertTrue(sockets.client.isClosed)
            assertFalse(owner.start())
            assertNull(owner.comparison())
        }
    }

    @Test
    fun factoryFailureClosesTransferredSocketWithoutChangingIdentity() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            assertFailsWith<IllegalArgumentException> {
                HandshakeV1Connection.adopt(sockets.client, server, capabilities, server.id, sockets.selectedAt, sockets.scheduler)
            }
            assertTrue(sockets.client.isClosed)
        }
        withSockets(client, server) { sockets ->
            val failure = AssertionError("test-only clock failure")
            assertSame(failure, assertFailsWith<AssertionError> {
                HandshakeV1Connection.adopt(sockets.client, client, capabilities, server.id, sockets.selectedAt, sockets.scheduler) { throw failure }
            })
            assertTrue(sockets.client.isClosed)
        }
    }

    @Test
    fun approvalBeforeHelloClosesEvenOnAnAuthenticatedSocket() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                val remote = HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream)
                remote.write(ProtocolHandshakeFrame.Approve(ProtocolHandshakeApproval(server.id, client.id, "cHJvb2Y=")))
                assertFalse(owner.readNext())
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.UnexpectedMessage)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun helloIdentityAndCapabilityFailuresCloseOwnedResources() = withPeers { client, server ->
        val cases = listOf(
            ProtocolHandshakeParticipant(foreignId(client, server), randomNonce(), capabilities) to ProtocolHandshakeFailure.IdentityMismatch,
            ProtocolHandshakeParticipant(server.id, randomNonce(), ProtocolCapabilities(2, setOf("text"), setOf("text"))) to null,
        )
        for ((hello, expected) in cases) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream).write(ProtocolHandshakeFrame.Hello(hello))
                assertFalse(owner.readNext())
                val failure = assertIs<HandshakeV1ConnectionFailure.Handshake>(assertIs<HandshakeV1ConnectionState.Closed>(owner.state).reason)
                if (expected != null) assertEquals(expected, failure.reason) else assertIs<ProtocolHandshakeFailure.Incompatible>(failure.reason)
                assertTrue(sockets.client.isClosed)
                assertNull(owner.comparison())
            }
        }
    }

    @Test
    fun malformedAndTruncatedTlsFramesCloseAndRethrowWithoutAuthorization() = withPeers { client, server ->
        val invalid = listOf(
            header(0), header(-1), header(ProtocolHandshakeFrameCodec.MAX_BYTES + 1),
            framed("{\"sensitive-peer-content\":true}".encodeToByteArray()),
            framed(byteArrayOf(0xc3.toByte(), 0x28)),
        )
        for (bytes in invalid) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                sockets.server.outputStream.apply { write(bytes); flush() }
                assertFailsWith<InvalidHandshakeV1FrameException> { owner.readNext() }
                assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.InvalidFrame), owner.state)
                assertTrue(sockets.client.isClosed)
            }
        }
        for (bytes in listOf(byteArrayOf(0, 0), header(10) + byteArrayOf(1, 2))) withSockets(client, server) { sockets ->
            sockets.clientOwner().use { owner ->
                assertTrue(owner.start())
                sockets.server.outputStream.apply { write(bytes); flush() }
                sockets.server.shutdownOutput()
                assertFailsWith<EOFException> { owner.readNext() }
                assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), owner.state)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun peerDisconnectAndFailedApprovalWriteInvalidateComparison() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val comparison = assertNotNull(left.comparison())
                    right.close()
                    assertFailsWith<IOException> { left.readNext() }
                    assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), left.state)
                    assertFalse(left.confirm(comparison))
                    assertTrue(sockets.client.isClosed)
                }
            }
        }
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val comparison = assertNotNull(left.comparison())
                    sockets.client.shutdownOutput()
                    assertFailsWith<IOException> { left.confirm(comparison) }
                    assertEquals(HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Io), left.state)
                    assertTrue(sockets.client.isClosed)
                }
            }
        }
    }

    @Test
    fun cancellationReleasesConcurrentReaderAndCannotBeUndone() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val readerEntered = CountDownLatch(1)
            var signalReader = false
            val owner = sockets.clientOwner(now = {
                if (signalReader) readerEntered.countDown()
                monotonicMillis()
            })
            sockets.serverOwner().use { remote ->
                owner.use {
                    exchangeHellos(owner, remote)
                    val comparison = assertNotNull(owner.comparison())
                    signalReader = true
                    val executor = Executors.newSingleThreadExecutor()
                    try {
                        val reading = executor.submit<Boolean> {
                            try { owner.readNext() } catch (_: IOException) { false }
                        }
                        assertTrue(readerEntered.await(5, TimeUnit.SECONDS))
                        owner.close()
                        assertFalse(reading.get(5, TimeUnit.SECONDS))
                        assertHandshakeClosed(owner, ProtocolHandshakeFailure.Cancelled)
                        assertTrue(sockets.client.isClosed)
                        assertFalse(owner.confirm(comparison))
                    } finally {
                        owner.close()
                        executor.shutdownNow()
                        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun readingStateAtExactDeadlineClosesSocketEvenWithoutTimer() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            var now = 1000L
            sockets.clientOwner(selectedAt = now, now = { now }).use { owner ->
                assertTrue(owner.start())
                now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertTrue(sockets.client.isClosed)
                assertFalse(owner.start())
            }
        }
    }

    @Test
    fun silentPeerCannotKeepReadAliveBeyondTheSelectionBudget() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1000
            sockets.clientOwner(selectedAt = selectedAt).use { owner ->
                assertTrue(owner.start())
                assertFailsWith<IOException> { owner.readNext() }
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertTrue(sockets.client.isClosed)
            }
        }
    }

    @Test
    fun previousConnectionComparisonCannotConfirmFreshNonces() = withPeers { client, server ->
        var previous: ProtocolHandshakeComparison? = null
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    previous = assertNotNull(left.comparison())
                }
            }
        }
        withSockets(client, server) { sockets ->
            sockets.clientOwner().use { left ->
                sockets.serverOwner().use { right ->
                    exchangeHellos(left, right)
                    val current = assertNotNull(left.comparison())
                    assertNotEquals(digest(assertNotNull(previous).bytes), digest(current.bytes))
                    assertFalse(left.confirm(assertNotNull(previous)))
                    assertEquals(active(ProtocolHandshakeState.AwaitingConfirmation(false)), left.state)
                    assertTrue(left.confirm(current))
                }
            }
        }
    }

    @Test
    fun scheduledDeadlineClosesIdleSocketWithoutAnyReaderOrStateInspection() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 500
            sockets.clientOwner(selectedAt = selectedAt).use { owner ->
                val afterDeadline = CountDownLatch(1)
                sockets.scheduler.schedule({ afterDeadline.countDown() }, 700, TimeUnit.MILLISECONDS)
                assertTrue(afterDeadline.await(5, TimeUnit.SECONDS))
                // Check the physical socket BEFORE a state read can enforce expiry itself.
                assertTrue(sockets.client.isClosed)
                assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                assertFalse(sockets.scheduler.isShutdown)
            }
        }
    }

    @Test
    fun unavailableDeadlineSchedulerCannotLeaveTransferredSocketOpen() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            sockets.scheduler.shutdown()
            assertFailsWith<RejectedExecutionException> { sockets.clientOwner() }
            assertTrue(sockets.client.isClosed)
        }
    }

    @Test
    fun membershipCloseAndOriginalDeadlineAbortPendingReceiveWithoutAuthorizingTraffic() = withPeers { client, server ->
        for (expire in listOf(false, true)) withSockets(client, server) { sockets ->
            val feature = GroupMembershipEvidenceCodec.FEATURE
            val negotiated = ProtocolCapabilities(1, setOf(feature), setOf(feature))
            val selectedAt = if (expire) monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1_500 else sockets.selectedAt
            sockets.clientOwner(selectedAt = selectedAt, supported = negotiated).use { left ->
                sockets.serverOwner(selectedAt = selectedAt, supported = negotiated).use { right ->
                    exchangeHellos(left, right)
                    val clientFirst = client.id < server.id
                    val owner = if (clientFirst) left else right
                    val identity = if (clientFirst) client else server
                    val peerSocket = if (clientFirst) sockets.server else sockets.client
                    val ownSocket = if (clientFirst) sockets.client else sockets.server
                    val evidence = GroupMembershipEvidence(GroupTrustAnchor(randomNonce(), identity.id), identity.id, null)
                    val worker = Executors.newSingleThreadExecutor()
                    try {
                        val result = worker.submit<GroupMembershipEvidence?> {
                            try { owner.exchangeMembership(evidence) } catch (_: IOException) { null }
                        }
                        // Observe the actual write on mutual TLS, then withhold the response.
                        // The owner is entering/read-blocked on the original same connection.
                        peerSocket.soTimeout = 5_000
                        assertEquals(identity.id, HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                            .readMembership {}.memberIdentity)
                        if (!expire) owner.close()
                        assertNull(result.get(5, TimeUnit.SECONDS))
                        assertTrue(owner.state is HandshakeV1ConnectionState.Closed)
                        assertTrue(ownSocket.isClosed)
                        assertFalse(sockets.scheduler.isShutdown)
                        assertNull(owner.comparison())
                    } finally { worker.shutdownNow() }
                }
            }
        }
    }

    @Test
    fun untrustedMembershipExchangeCannotReuseBootstrapComparisonOrTransferToAdmission() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val feature = GroupMembershipEvidenceCodec.FEATURE
            val negotiated = ProtocolCapabilities(1, setOf(feature), setOf(feature))
            sockets.clientOwner(supported = negotiated).use { left ->
                sockets.serverOwner(supported = negotiated).use { right ->
                    exchangeHellos(left, right)
                    val oldLeft = assertNotNull(left.comparison())
                    val oldRight = assertNotNull(right.comparison())
                    val local = GroupMembershipEvidence(GroupTrustAnchor(randomNonce(), client.id), client.id, null)
                    val remote = GroupMembershipEvidence(GroupTrustAnchor(randomNonce(), server.id), server.id, null)
                    val workers = Executors.newFixedThreadPool(2)
                    try {
                        val a = workers.submit<GroupMembershipEvidence?> { left.exchangeMembership(local) }
                        val b = workers.submit<GroupMembershipEvidence?> { right.exchangeMembership(remote) }
                        assertEquals(server.id, assertNotNull(a.get(5, TimeUnit.SECONDS)).memberIdentity)
                        assertEquals(client.id, assertNotNull(b.get(5, TimeUnit.SECONDS)).memberIdentity)
                        assertNull(left.comparison())
                        assertNull(right.comparison())
                        assertFalse(left.confirm(oldLeft))
                        assertFalse(right.confirm(oldRight))
                        assertFalse(left.readNext())
                        // Encoding fixture only: the admission gate must reject BEFORE using it.
                        val proof = lantern.protocol.FounderGroupAdmissionDraft.prepare(local.anchor, client.id, server.id)
                            .withSignature("AAAA")
                        assertNull(left.transferToGroup(local.anchor, proof, emptyMap()))
                    } finally { workers.shutdownNow() }
                }
            }
        }
    }

    private fun exchangeHellos(left: HandshakeV1Connection, right: HandshakeV1Connection) {
        assertTrue(left.start())
        assertFalse(left.start())
        assertTrue(right.start())
        assertTrue(left.readNext())
        assertTrue(right.readNext())
    }

    @Test
    fun sessionRequiresBothFeaturesOnBothHelloOffersBeforeAnyProofIo() = withPeers { client, server ->
        val membership = GroupMembershipEvidenceCodec.FEATURE
        val session = GroupSessionOfferCodec.FEATURE
        val supported = setOf(membership, session)
        val agreed = ProtocolCapabilities(1, supported, supported)
        val onlyMembership = ProtocolCapabilities(1, supported, setOf(membership))
        val onlySession = ProtocolCapabilities(1, supported, setOf(session))
        for ((localCaps, remoteCaps) in listOf(onlyMembership to agreed, agreed to onlyMembership,
            onlySession to agreed, agreed to onlySession)) {
            withSockets(client, server) { sockets ->
                sockets.clientOwner(supported = localCaps).use { left ->
                    sockets.serverOwner(supported = remoteCaps).use { right ->
                        exchangeHellos(left, right)
                        val anchor = GroupTrustAnchor(randomNonce(), client.id)
                        val local = GroupMembershipEvidence(anchor, client.id, null)
                        val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false))
                        var verified = false
                        assertFailsWith<IllegalStateException> {
                            left.negotiateSession(local, offer) { verified = true; true }
                        }
                        assertFalse(verified)
                        assertTrue(sockets.client.isClosed)
                        assertFailsWith<IOException> {
                            HandshakeV1FrameStream(sockets.server.inputStream, sockets.server.outputStream).readMembership {}
                        }
                    }
                }
            }
        }
    }

    @Test
    fun liveSessionExchangeKeepsUsedChoiceAndPermanentlyDisablesBootstrapAndAdmission() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val features = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)
            val caps = ProtocolCapabilities(1, features, features)
            sockets.clientOwner(supported = caps).use { left -> sockets.serverOwner(supported = caps).use { right ->
                exchangeHellos(left, right)
                val oldLeft = assertNotNull(left.comparison())
                val oldRight = assertNotNull(right.comparison())
                val anchor = GroupTrustAnchor(randomNonce(), client.id)
                val local = GroupMembershipEvidence(anchor, client.id, null)
                val draft = FounderGroupAdmissionDraft.prepare(anchor, client.id, server.id)
                val proof = draft.withSignature(client.sign(draft.signedBytes()))
                val remote = GroupMembershipEvidence(anchor, server.id, GroupAdmissionEvidence(proof, listOf(
                    GroupAdmissionCertificate(client.id, Base64.getEncoder().encodeToString(client.certificate.encoded)))))
                val a = GroupSessionOffer(SessionCandidate(anchor.groupId, "a".repeat(64), true))
                val b = GroupSessionOffer(SessionCandidate(anchor.groupId, "b".repeat(64), true))
                val workers = Executors.newFixedThreadPool(2)
                try {
                    val x = workers.submit<GroupSessionOffer?> {
                        left.negotiateSession(local, a) { verifyPeerMembership(it, anchor, server.id) }
                    }
                    val y = workers.submit<GroupSessionOffer?> {
                        right.negotiateSession(remote, b) { verifyPeerMembership(it, anchor, client.id) }
                    }
                    assertEquals(b, x.get(5, TimeUnit.SECONDS))
                    assertEquals(a, y.get(5, TimeUnit.SECONDS))
                    assertIs<lantern.domain.SessionSelection.Choose>(a.select(anchor, b))
                    assertNull(left.comparison())
                    assertNull(right.comparison())
                    assertFalse(left.confirm(oldLeft))
                    assertFalse(right.confirm(oldRight))
                    assertFalse(left.readNext())
                    assertNull(left.transferToGroup(anchor, proof, emptyMap()))
                    assertFailsWith<IllegalStateException> { left.negotiateSession(local, a) { true } }
                    assertTrue(left.state is HandshakeV1ConnectionState.Closed)
                } finally {
                    workers.shutdownNow()
                    assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
                }
            } }
        }
    }

    @Test
    fun sessionCancelAndOriginalDeadlineAbortAfterLiveMembershipBeforeRemoteSessionArrives() = withPeers { client, server ->
        for (expire in listOf(false, true)) withSockets(client, server) { sockets ->
            val features = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)
            val caps = ProtocolCapabilities(1, features, features)
            val selectedAt = if (expire) monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 2_000 else sockets.selectedAt
            sockets.clientOwner(selectedAt = selectedAt, supported = caps).use { left ->
                sockets.serverOwner(selectedAt = selectedAt, supported = caps).use { right ->
                    exchangeHellos(left, right)
                    val ownIdentity = if (client.id < server.id) client else server
                    val peerIdentity = if (client.id < server.id) server else client
                    val owner = if (client.id < server.id) left else right
                    val ownSocket = if (client.id < server.id) sockets.client else sockets.server
                    val peerSocket = if (client.id < server.id) sockets.server else sockets.client
                    val anchor = GroupTrustAnchor(randomNonce(), ownIdentity.id)
                    val local = GroupMembershipEvidence(anchor, ownIdentity.id, null)
                    val draft = FounderGroupAdmissionDraft.prepare(anchor, ownIdentity.id, peerIdentity.id)
                    val remote = GroupMembershipEvidence(anchor, peerIdentity.id,
                        GroupAdmissionEvidence(draft.withSignature(ownIdentity.sign(draft.signedBytes())), listOf(
                            GroupAdmissionCertificate(ownIdentity.id, Base64.getEncoder().encodeToString(ownIdentity.certificate.encoded)))))
                    val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false), established = false)
                    val stream = HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                    val worker = Executors.newSingleThreadExecutor()
                    try {
                        val result = worker.submit<GroupSessionOffer?> {
                            try { owner.negotiateSession(local, offer) { verifyPeerMembership(it, anchor, peerIdentity.id) } }
                            catch (_: IOException) { null }
                        }
                        assertEquals(ownIdentity.id, stream.readMembership {}.memberIdentity)
                        stream.writeMembership(remote)
                        // Actual session bytes imply the real P-256 membership was verified first.
                        assertEquals(offer, stream.readSessionOffer {})
                        if (!expire) owner.close()
                        assertNull(result.get(5, TimeUnit.SECONDS))
                        assertTrue(ownSocket.isClosed)
                        assertNull(owner.comparison())
                        assertFalse(sockets.scheduler.isShutdown)
                        if (expire) assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                    } finally {
                        worker.shutdownNow()
                        assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun wrongMembershipNeverWritesSessionEvenWhenPeerPrequeuesAnOffer() = withPeers { client, server ->
        withSockets(client, server) { sockets ->
            val features = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE)
            val caps = ProtocolCapabilities(1, features, features)
            sockets.clientOwner(supported = caps).use { left -> sockets.serverOwner(supported = caps).use { right ->
                exchangeHellos(left, right)
                val ownIdentity = if (client.id < server.id) client else server
                val peerIdentity = if (client.id < server.id) server else client
                val owner = if (client.id < server.id) left else right
                val peerSocket = if (client.id < server.id) sockets.server else sockets.client
                val anchor = GroupTrustAnchor(randomNonce(), ownIdentity.id)
                val other = GroupTrustAnchor(randomNonce(), peerIdentity.id)
                val local = GroupMembershipEvidence(anchor, ownIdentity.id, null)
                val remote = GroupMembershipEvidence(other, peerIdentity.id, null)
                val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false))
                val stream = HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                val worker = Executors.newSingleThreadExecutor()
                try {
                    val result = worker.submit<Boolean> {
                        assertFailsWith<IllegalStateException> {
                            owner.negotiateSession(local, offer) { verifyPeerMembership(it, anchor, peerIdentity.id) }
                        }
                        true
                    }
                    stream.readMembership {}
                    stream.writeMembership(remote)
                    // Coalesced/early untrusted bytes cannot bypass proof verification.
                    try { stream.writeSessionOffer(offer) } catch (_: IOException) { /* Owner already rejected. */ }
                    assertTrue(result.get(5, TimeUnit.SECONDS))
                    assertFailsWith<IOException> { stream.readSessionOffer {} }
                    assertTrue(owner.state is HandshakeV1ConnectionState.Closed)
                } finally {
                    worker.shutdownNow()
                    assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
                }
            } }
        }
    }

    private fun active(state: ProtocolHandshakeState) = HandshakeV1ConnectionState.Active(state)

    @Test
    fun rosterTextScopeWrongAckCancelAndOriginalDeadlineCannotAcknowledgeAfterFreshRoster() = withPeers { client, server ->
        for (action in listOf("scope", "ack", "cancel", "expiry")) withSockets(client, server) { sockets ->
            val author = if (client.id < server.id) client else server
            val recipient = if (client.id < server.id) server else client
            val required = GroupRosterTextCodec.requiredFeatures
            val senderCaps = ProtocolCapabilities(1, required + GroupTextTransferCodec.SENDER_FEATURE, required)
            val receiverCaps = ProtocolCapabilities(1, required + GroupTextTransferCodec.RECEIVER_FEATURE, required)
            val selectedAt = if (action == "expiry") monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 2_000 else sockets.selectedAt
            sockets.clientOwner(selectedAt = selectedAt, supported = if (client === author) senderCaps else receiverCaps).use { left ->
                sockets.serverOwner(selectedAt = selectedAt, supported = if (server === author) senderCaps else receiverCaps).use { right ->
                    exchangeHellos(left, right)
                    val owner = if (client === author) left else right
                    val peerSocket = if (client === author) sockets.server else sockets.client
                    val anchor = GroupTrustAnchor(randomNonce(), author.id)
                    val membership = GroupMembershipEvidence(anchor, author.id, null)
                    val draft = FounderGroupAdmissionDraft.prepare(anchor, author.id, recipient.id)
                    val peerMembership = GroupMembershipEvidence(anchor, recipient.id,
                        GroupAdmissionEvidence(draft.withSignature(author.sign(draft.signedBytes())), listOf(
                            GroupAdmissionCertificate(author.id, Base64.getEncoder().encodeToString(author.certificate.encoded)))))
                    val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false), false)
                    fun roster(identity: Identity, proof: GroupMembershipEvidence): GroupSessionRoster {
                        val certificate = GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(identity.certificate.encoded))
                        val bytes = GroupSessionRosterCodec.signingBytes(offer.session.sessionId, proof, certificate)
                        return GroupSessionRoster(anchor, offer.session.sessionId,
                            listOf(GroupSessionJoin(offer.session.sessionId, proof, certificate, identity.sign(bytes))))
                    }
                    val local = roster(author, membership)
                    val remote = roster(recipient, peerMembership)
                    val installed = java.util.concurrent.atomic.AtomicBoolean()
                    val outgoingCalled = java.util.concurrent.atomic.AtomicBoolean()
                    val acknowledged = java.util.concurrent.atomic.AtomicBoolean()
                    val stream = HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                    val worker = Executors.newSingleThreadExecutor()
                    try {
                        val result = worker.submit<Boolean> {
                            try {
                                owner.transferRosterText(membership, offer, true,
                                    verifyRemote = { verifyPeerMembership(it, anchor, recipient.id) },
                                    propose = { assertEquals(offer, it); local },
                                    mergeVerified = { a, b ->
                                        GroupRootAdoptionJournalInspector.withVerifier { verify -> check(a.verify(verify) && b.verify(verify)) }
                                        a.merge(b)
                                    }, installRoster = { installed.set(true) },
                                    outgoing = { context ->
                                        outgoingCalled.set(true)
                                        val content = GroupTextContent("00000000-0000-0000-0000-000000000001", anchor.groupId,
                                            context.sessionId, author.id, 1, 1, context.recipients, "Ricevuta per un solo dispositivo")
                                        SignedGroupText(content, author.sign(GroupTextCodec.signedBytes(content)))
                                    }, incoming = { _, _, _ -> error("Sender cannot receive") }, completed = { acknowledged.set(true) })
                                true
                            } catch (_: Exception) { false }
                        }
                        stream.readMembership {}; stream.writeMembership(peerMembership)
                        assertEquals(offer, stream.readSessionOffer {}); stream.writeSessionOffer(offer)
                        stream.readRosterControl(false) {}; stream.writeRosterControl(GroupSessionRosterCodec.encode(remote))
                        val agreement = stream.readRosterControl(true) {}; stream.writeRosterControl(agreement)
                        val scope = stream.readRosterTextControl(GroupRosterTextCodec.SCOPE_BYTES) {}
                        stream.writeTextControl(if (action == "scope") scope.copyOf().also { it[it.lastIndex] = 0 } else scope)
                        if (action != "scope") {
                            stream.readGroupText {}
                            if (action == "ack") stream.writeTextControl(ByteArray(GroupRosterTextCodec.ACK_BYTES))
                            if (action == "cancel") owner.close()
                        }
                        assertFalse(result.get(4, TimeUnit.SECONDS))
                        assertTrue(installed.get())
                        assertEquals(action != "scope", outgoingCalled.get())
                        assertFalse(acknowledged.get())
                        assertFailsWith<IOException> { owner.negotiateSession(membership, offer) { true } }
                    } finally {
                        owner.close(); worker.shutdownNow()
                        assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun groupTextScopeMismatchWrongAckCancelAndOriginalDeadlineNeverAcknowledge() = withPeers { client, server ->
        for (action in listOf("scope", "ack", "cancel", "expiry")) withSockets(client, server) { sockets ->
            val senderIdentity = if (client.id < server.id) client else server
            val recipientIdentity = if (client.id < server.id) server else client
            val features = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE, GroupTextTransferCodec.FEATURE)
            val senderCaps = ProtocolCapabilities(1, features + GroupTextTransferCodec.SENDER_FEATURE, features)
            val receiverCaps = ProtocolCapabilities(1, features + GroupTextTransferCodec.RECEIVER_FEATURE, features)
            val selectedAt = if (action == "expiry") monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 2_000 else sockets.selectedAt
            sockets.clientOwner(selectedAt = selectedAt, supported = if (client === senderIdentity) senderCaps else receiverCaps).use { left ->
                sockets.serverOwner(selectedAt = selectedAt, supported = if (server === senderIdentity) senderCaps else receiverCaps).use { right ->
                    exchangeHellos(left, right)
                    val owner = if (client === senderIdentity) left else right
                    val peerSocket = if (client === senderIdentity) sockets.server else sockets.client
                    val anchor = GroupTrustAnchor(randomNonce(), senderIdentity.id)
                    val membership = GroupMembershipEvidence(anchor, senderIdentity.id, null)
                    val draft = FounderGroupAdmissionDraft.prepare(anchor, senderIdentity.id, recipientIdentity.id)
                    val peerMembership = GroupMembershipEvidence(anchor, recipientIdentity.id,
                        GroupAdmissionEvidence(draft.withSignature(senderIdentity.sign(draft.signedBytes())), listOf(
                            GroupAdmissionCertificate(senderIdentity.id, Base64.getEncoder().encodeToString(senderIdentity.certificate.encoded)))))
                    val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false), established = false)
                    val context = GroupTextTransferContext(anchor.groupId, offer.session.sessionId, senderIdentity.id, recipientIdentity.id)
                    val outgoingCalled = java.util.concurrent.atomic.AtomicBoolean()
                    val acknowledged = java.util.concurrent.atomic.AtomicBoolean()
                    val worker = Executors.newSingleThreadExecutor()
                    val stream = HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                    try {
                        val result = worker.submit<Boolean> {
                            try {
                                owner.transferGroupText(membership, offer, true,
                                    verifyRemote = { verifyPeerMembership(it, anchor, recipientIdentity.id) },
                                    selectSession = { assertEquals(offer, it); context },
                                    outgoing = {
                                        outgoingCalled.set(true)
                                        val c = GroupTextContent("00000000-0000-0000-0000-000000000001", anchor.groupId,
                                            context.sessionId, senderIdentity.id, 1, 1, context.recipients, "No falso ACK")
                                        SignedGroupText(c, senderIdentity.sign(GroupTextCodec.signedBytes(c)))
                                    }, incoming = { _, _, _ -> error("Sender cannot receive") },
                                    completed = { acknowledged.set(true) })
                                true
                            } catch (_: Exception) { false }
                        }
                        stream.readMembership {}
                        stream.writeMembership(peerMembership)
                        assertEquals(offer, stream.readSessionOffer {})
                        stream.writeSessionOffer(offer)
                        val scope = stream.readTextControl(GroupTextTransferCodec.SCOPE_BYTES) {}
                        stream.writeTextControl(if (action == "scope") ByteArray(scope.size) else scope)
                        if (action != "scope") {
                            val message = stream.readGroupText {}
                            assertTrue(Identity.verify(senderIdentity.certificate, GroupTextCodec.signedBytes(message.content), message.signature))
                            when (action) {
                                "ack" -> stream.writeTextControl(ByteArray(GroupTextTransferCodec.ACK_BYTES))
                                "cancel" -> owner.close()
                                "expiry" -> Unit // Original timer must abort the pending ACK read itself.
                            }
                        }
                        assertFalse(result.get(5, TimeUnit.SECONDS))
                        assertEquals(action != "scope", outgoingCalled.get())
                        assertFalse(acknowledged.get())
                        assertNull(owner.comparison())
                        if (action == "expiry") assertHandshakeClosed(owner, ProtocolHandshakeFailure.Expired)
                    } finally {
                        owner.close()
                        worker.shutdownNow()
                        assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    private fun assertReady(owner: HandshakeV1Connection) = assertEquals(
        active(ProtocolHandshakeState.Ready(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text")))), owner.state,
    )

    private fun assertHandshakeClosed(owner: HandshakeV1Connection, reason: ProtocolHandshakeFailure) = assertEquals(
        HandshakeV1ConnectionState.Closed(HandshakeV1ConnectionFailure.Handshake(reason)), owner.state,
    )

    private fun foreignId(client: Identity, server: Identity) = listOf("c", "d", "e").map { it.repeat(64) }.first { it != client.id && it != server.id }
    private fun monotonicMillis() = System.nanoTime() / 1_000_000

    private fun header(length: Int) = java.io.ByteArrayOutputStream().also { DataOutputStream(it).writeInt(length) }.toByteArray()
    private fun framed(payload: ByteArray) = header(payload.size) + payload

    /** Test-only option failure; the session and terminal I/O still use the real pinned TLS socket. */
    @Test
    fun rosterInvalidJoinRootSessionAgreementAndPendingCancelOrDeadlineCannotInstall() = withPeers { client, server ->
        val localIdentity = minOf(client, server, compareBy { it.id })
        val peerIdentity = if (localIdentity === client) server else client
        val required = setOf(GroupMembershipEvidenceCodec.FEATURE, GroupSessionOfferCodec.FEATURE, GroupSessionRosterCodec.FEATURE)
        val rosterCaps = ProtocolCapabilities(1, required, required)
        for (action in listOf("signature", "root", "session", "agreement", "cancel", "expiry")) withSockets(client, server) { sockets ->
            val selectedAt = if (action == "expiry") monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 2_000 else sockets.selectedAt
            sockets.clientOwner(selectedAt = selectedAt, supported = rosterCaps).use { left ->
                sockets.serverOwner(selectedAt = selectedAt, supported = rosterCaps).use { right ->
                    exchangeHellos(left, right)
                    val owner = if (localIdentity === client) left else right
                    val peerSocket = if (localIdentity === client) sockets.server else sockets.client
                    val anchor = GroupTrustAnchor(randomNonce(), localIdentity.id)
                    val localMembership = GroupMembershipEvidence(anchor, localIdentity.id, null)
                    val draft = FounderGroupAdmissionDraft.prepare(anchor, localIdentity.id, peerIdentity.id)
                    val peerMembership = GroupMembershipEvidence(anchor, peerIdentity.id,
                        GroupAdmissionEvidence(draft.withSignature(localIdentity.sign(draft.signedBytes())), listOf(
                            GroupAdmissionCertificate(localIdentity.id, Base64.getEncoder().encodeToString(localIdentity.certificate.encoded)))))
                    val offer = GroupSessionOffer(SessionCandidate(anchor.groupId, randomNonce(), false), false)
                    fun join(identity: Identity, proof: GroupMembershipEvidence, session: String, wrongSignature: Boolean = false): GroupSessionJoin {
                        val certificate = GroupAdmissionCertificate(identity.id, Base64.getEncoder().encodeToString(identity.certificate.encoded))
                        val bytes = GroupSessionRosterCodec.signingBytes(session, proof, certificate)
                        return GroupSessionJoin(session, proof, certificate, (if (wrongSignature) localIdentity else identity).sign(bytes))
                    }
                    val local = GroupSessionRoster(anchor, offer.session.sessionId, listOf(join(localIdentity, localMembership, offer.session.sessionId)))
                    val remoteAnchor = if (action == "root") GroupTrustAnchor(randomNonce(), peerIdentity.id) else anchor
                    val remoteSession = if (action == "session") randomNonce() else offer.session.sessionId
                    val remoteProof = if (action == "root") GroupMembershipEvidence(remoteAnchor, peerIdentity.id, null) else peerMembership
                    val remote = GroupSessionRoster(remoteAnchor, remoteSession, listOf(join(peerIdentity, remoteProof, remoteSession, action == "signature")))
                    val completed = java.util.concurrent.atomic.AtomicBoolean()
                    val worker = Executors.newSingleThreadExecutor()
                    val stream = HandshakeV1FrameStream(peerSocket.inputStream, peerSocket.outputStream)
                    try {
                        val result = worker.submit<Boolean> {
                            try {
                                owner.synchronizeRoster(localMembership, offer,
                                    verifyRemote = { verifyPeerMembership(it, anchor, peerIdentity.id) }, propose = { assertEquals(offer, it); local },
                                    mergeVerified = { a, b ->
                                        GroupRootAdoptionJournalInspector.withVerifier { verify -> check(a.verify(verify) && b.verify(verify)) }
                                        a.merge(b)
                                    }, completed = { completed.set(true) })
                                true
                            } catch (_: Exception) { false }
                        }
                        stream.readMembership {}
                        stream.writeMembership(peerMembership)
                        assertEquals(offer, stream.readSessionOffer {})
                        stream.writeSessionOffer(offer)
                        assertContentEquals(GroupSessionRosterCodec.encode(local), stream.readRosterControl(false) {})
                        stream.writeRosterControl(GroupSessionRosterCodec.encode(remote))
                        if (action in listOf("agreement", "cancel", "expiry")) {
                            val agreement = stream.readRosterControl(true) {}
                            if (action == "agreement") stream.writeRosterControl(agreement.copyOf().also { it[it.lastIndex] = 0 })
                            if (action == "cancel") owner.close()
                        }
                        assertFalse(result.get(4, TimeUnit.SECONDS))
                        assertFalse(completed.get())
                        assertFailsWith<IOException> { owner.negotiateSession(localMembership, offer) { true } }
                    } finally {
                        owner.close()
                        worker.shutdownNow()
                        assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS))
                    }
                }
            }
        }
    }

    @Test
    fun rosterVerifierCacheNeverAcceptsDifferentDerForAnAlreadyVerifiedIdentity() = withPeers { a, b ->
        val bytes = "certificate cache binding".encodeToByteArray()
        val valid = GroupAdmissionCertificate(a.id, Base64.getEncoder().encodeToString(a.certificate.encoded))
        val substituted = GroupAdmissionCertificate(a.id, Base64.getEncoder().encodeToString(b.certificate.encoded))
        GroupRootAdoptionJournalInspector.withVerifier { verify ->
            assertTrue(verify(valid, bytes, a.sign(bytes)))
            assertFailsWith<IllegalStateException> { verify(substituted, bytes, a.sign(bytes)) }
            assertTrue(verify(valid, bytes, a.sign(bytes)))
        }
    }

    private class LingerFailureSocket(private val delegate: SSLSocket, private val failure: IOException) : SSLSocket() {
        var lingerAttempts = 0
            private set

        override fun setSoLinger(on: Boolean, linger: Int) {
            lingerAttempts++
            throw failure
        }
        override fun getSession() = delegate.session
        override fun isClosed() = delegate.isClosed
        override fun shutdownInput() = delegate.shutdownInput()
        override fun close() = delegate.close()
        override fun getSupportedCipherSuites() = delegate.supportedCipherSuites
        override fun getEnabledCipherSuites() = delegate.enabledCipherSuites
        override fun setEnabledCipherSuites(suites: Array<out String>) { delegate.enabledCipherSuites = suites }
        override fun getSupportedProtocols() = delegate.supportedProtocols
        override fun getEnabledProtocols() = delegate.enabledProtocols
        override fun setEnabledProtocols(protocols: Array<out String>) { delegate.enabledProtocols = protocols }
        override fun addHandshakeCompletedListener(listener: javax.net.ssl.HandshakeCompletedListener) = delegate.addHandshakeCompletedListener(listener)
        override fun removeHandshakeCompletedListener(listener: javax.net.ssl.HandshakeCompletedListener) = delegate.removeHandshakeCompletedListener(listener)
        override fun startHandshake() = delegate.startHandshake()
        override fun setUseClientMode(mode: Boolean) { delegate.useClientMode = mode }
        override fun getUseClientMode() = delegate.useClientMode
        override fun setNeedClientAuth(need: Boolean) { delegate.needClientAuth = need }
        override fun getNeedClientAuth() = delegate.needClientAuth
        override fun setWantClientAuth(want: Boolean) { delegate.wantClientAuth = want }
        override fun getWantClientAuth() = delegate.wantClientAuth
        override fun setEnableSessionCreation(flag: Boolean) { delegate.enableSessionCreation = flag }
        override fun getEnableSessionCreation() = delegate.enableSessionCreation
    }

    private inner class Sockets(val client: SSLSocket, val server: SSLSocket, val clientIdentity: Identity, val serverIdentity: Identity, val selectedAt: Long, val scheduler: ScheduledExecutorService) {
        fun clientOwner(selectedAt: Long = this.selectedAt, now: () -> Long = ::monotonicMillis,
            supported: ProtocolCapabilities = capabilities) = HandshakeV1Connection.adopt(
            client, clientIdentity, supported, serverIdentity.id, selectedAt, scheduler, now,
        )
        fun serverOwner(selectedAt: Long = this.selectedAt, supported: ProtocolCapabilities = capabilities) =
            HandshakeV1Connection.adopt(server, serverIdentity, supported, clientIdentity.id, selectedAt, scheduler)
    }

    private fun withSockets(client: Identity, server: Identity, block: (Sockets) -> Unit) {
        val selectedAt = monotonicMillis()
        val loopback = InetAddress.getLoopbackAddress()
        val executor = Executors.newSingleThreadScheduledExecutor()
        val listener = server.context { it == client.id }.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
        listener.use {
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.soTimeout = 5000
            try {
                val accepting = executor.submit<SSLSocket> {
                    val socket = listener.accept() as SSLSocket
                    try {
                        socket.soTimeout = 5000
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        socket.startHandshake()
                        socket
                    } catch (error: Throwable) {
                        socket.close()
                        throw error
                    }
                }
                (client.context { it == server.id }.socketFactory.createSocket(loopback, listener.localPort) as SSLSocket).use { clientSocket ->
                    clientSocket.soTimeout = 5000
                    clientSocket.enabledProtocols = arrayOf("TLSv1.3")
                    clientSocket.startHandshake()
                    accepting.get(5, TimeUnit.SECONDS).use { serverSocket ->
                        block(Sockets(clientSocket, serverSocket, client, server, selectedAt, executor))
                    }
                }
            } finally {
                listener.close()
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    private fun withPeers(block: (Identity, Identity) -> Unit) {
        val directory = Files.createTempDirectory("lantern-v1-owner-test-")
        val password = "test-only-owner-passphrase".toCharArray()
        try {
            block(Identity.open(directory.resolve("client.p12"), password), Identity.open(directory.resolve("server.p12"), password))
        } finally {
            password.fill('\u0000')
            Files.walk(directory).use { files -> files.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }
}
