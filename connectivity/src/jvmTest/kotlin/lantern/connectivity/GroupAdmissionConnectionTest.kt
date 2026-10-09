package lantern.connectivity

import lantern.domain.GroupAdmissionClaim
import lantern.domain.GroupTrustAnchor
import lantern.protocol.GroupAdmissionBridgeFailure
import lantern.protocol.GroupAdmissionBridgeState
import lantern.protocol.GroupAdmissionChainResult
import lantern.protocol.GroupAdmissionCodec
import lantern.protocol.GroupAdmissionComparison
import lantern.protocol.GroupAdmissionConfirmation
import lantern.protocol.GroupAdmissionConfirmationContext
import lantern.protocol.GroupAdmissionConfirmationFailure
import lantern.protocol.GroupAdmissionConfirmationFrameDecoder
import lantern.protocol.GroupAdmissionConfirmationState
import lantern.protocol.GroupAdmissionProof
import lantern.protocol.ProtocolCapabilities
import lantern.protocol.ProtocolHandshakeAttempt
import lantern.protocol.ProtocolHandshakeFrame
import lantern.protocol.ProtocolHandshakeParticipant
import lantern.protocol.SignedGroupAdmission
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Real TLS/certificates/JCA. Test-only explicit UI clicks, injected clocks and I/O failures. */
class GroupAdmissionConnectionTest {
    @Test
    fun delegatedProofAndBothExplicitConfirmationsAreRequired() = withFixture { fixture ->
        fixture.clientOwner().use { left ->
            fixture.serverOwner().use { right ->
                assertEquals(GroupAdmissionBridgeState.AwaitingStart, left.state)
                assertFalse(left.readChunk())
                assertNull(left.comparison())
                assertTrue(left.prepare())
                assertFalse(left.prepare())
                assertTrue(right.prepare())
                val leftCode = assertNotNull(left.comparison())
                val rightCode = assertNotNull(right.comparison())
                assertEquals(digest(leftCode.bytes), digest(rightCode.bytes))
                assertTrue(left.confirm(leftCode))
                assertFalse(left.confirm(leftCode))
                assertTrue(right.readChunk())
                assertEquals(active(GroupAdmissionConfirmationState.AwaitingConfirmation(true)), right.state)
                assertEquals(active(GroupAdmissionConfirmationState.AwaitingRemoteConfirmation), left.state)
                assertTrue(right.confirm(rightCode))
                assertConfirmed(right)
                assertTrue(left.readChunk())
                assertConfirmed(left)
                assertFalse(fixture.scheduler.isShutdown)
                left.close()
                assertClosed(left, GroupAdmissionConfirmationFailure.Cancelled)
                assertTrue(fixture.clientSocket.isClosed)
                assertFalse(left.confirm(leftCode))
                assertNull(left.cleanupFailure)
            }
        }
        assertTrue(fixture.serverSocket.isClosed)
    }

    @Test
    fun missingOrSubstitutedFounderRefusesProofAndClosesImmediately() {
        for (substitute in listOf(false, true)) withFixture { fixture ->
            val certificates = if (substitute) mapOf(fixture.founder.id to fixture.member.certificate) else emptyMap()
            fixture.clientOwner(certificates = certificates).use { owner ->
                assertFalse(owner.prepare())
                assertTrue(fixture.clientSocket.isClosed) // Not dependent on a later state read.
                assertClosed(owner, GroupAdmissionConfirmationFailure.InvalidProof(GroupAdmissionChainResult.InvalidSignature(0)))
                assertNull(owner.comparison())
                assertFalse(owner.readChunk())
            }
        }
    }

    @Test
    fun actualTlsCertificatesOverrideMapEntriesForEndpoints() = withFixture { fixture ->
        val poisoned = fixture.certificates + mapOf(fixture.issuer.id to fixture.member.certificate)
        fixture.clientOwner(certificates = poisoned).use { owner ->
            assertTrue(owner.prepare())
            assertNotNull(owner.comparison())
        }
        fixture.serverOwner(certificates = poisoned).use { owner ->
            assertTrue(owner.prepare())
            assertNotNull(owner.comparison())
        }
    }

    @Test
    fun localIdentityAndSelectedPinMustMatchActualTls() {
        withFixture { fixture ->
            val owner = GroupAdmissionConnection.adopt(fixture.clientSocket, fixture.issuer,
                fixture.context, fixture.certificates, fixture.founder.id, fixture.selectedAt, fixture.scheduler)
            assertTrue(fixture.clientSocket.isClosed)
            assertClosed(owner, GroupAdmissionConfirmationFailure.IdentityMismatch)
            assertFalse(owner.prepare())
        }
        withFixture { fixture ->
            assertFailsWith<IllegalArgumentException> {
                GroupAdmissionConnection.adopt(fixture.clientSocket, fixture.member, fixture.context,
                    fixture.certificates, fixture.member.id, fixture.selectedAt, fixture.scheduler)
            }
            assertTrue(fixture.clientSocket.isClosed)
        }
    }

    @Test
    fun fragmentedTlsInputDoesNotConfirmUntilEntireSignatureArrives() = withFixture { fixture ->
        fixture.clientOwner().use { owner ->
            assertTrue(owner.prepare())
            val frame = remoteFrame(fixture)
            for ((index, byte) in frame.withIndex()) {
                fixture.serverSocket.outputStream.apply { write(byteArrayOf(byte)); flush() }
                assertTrue(owner.readChunk())
                assertEquals(active(GroupAdmissionConfirmationState.AwaitingConfirmation(index == frame.lastIndex)), owner.state)
            }
            assertTrue(owner.confirm(assertNotNull(owner.comparison())))
            assertConfirmed(owner)
        }
    }

    @Test
    fun malformedFramesAndBootstrapMessagesCloseWithSanitizedError() {
        val invalid = listOf(
            byteArrayOf(0, 0, 0, 0), byteArrayOf(-1, -1, -1, -1), byteArrayOf(0, 0, 4, 1),
            framed("{\"private-peer-content\":true}".encodeToByteArray()),
            framed(byteArrayOf(0xc3.toByte(), 0x28)),
            framed("{\"version\":1,\"type\":\"APPROVE\"}".encodeToByteArray()),
        )
        for (bytes in invalid) withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                fixture.serverSocket.outputStream.apply { write(bytes); flush() }
                val error = assertFailsWith<InvalidGroupAdmissionFrameException> { owner.readChunk() }
                assertEquals("Invalid group confirmation frame", error.message)
                assertNull(error.cause)
                assertTrue(fixture.clientSocket.isClosed)
                assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), owner.state)
            }
        }
    }

    @Test
    fun cleanEofRevokesConfirmedAndTruncatedEofRefuses() {
        withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture)); flush() }
                assertTrue(owner.readChunk())
                assertTrue(owner.confirm(assertNotNull(owner.comparison())))
                assertConfirmed(owner)
                fixture.serverSocket.shutdownOutput()
                assertFalse(owner.readChunk())
                assertTrue(fixture.clientSocket.isClosed)
                assertClosed(owner, GroupAdmissionConfirmationFailure.TransportClosed)
            }
        }
        for (size in listOf(1, 3, 4, 5)) withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture).copyOf(size)); flush() }
                assertTrue(owner.readChunk())
                fixture.serverSocket.shutdownOutput()
                assertFailsWith<InvalidGroupAdmissionFrameException> { owner.readChunk() }
                assertTrue(fixture.clientSocket.isClosed)
                assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), owner.state)
            }
        }
    }

    @Test
    fun duplicateOrDifferentContextConfirmationCannotGrantProgress() {
        withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                val frame = remoteFrame(fixture)
                fixture.serverSocket.outputStream.apply { write(frame + frame); flush() }
                // A provider may split the two frames: read only until the terminal state.
                while (!fixture.clientSocket.isClosed) owner.readChunk()
                assertClosed(owner, GroupAdmissionConfirmationFailure.UnexpectedConfirmation)
            }
        }
        withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                val altered = GroupAdmissionConfirmationContext(
                    fixture.issuerOffer, ProtocolHandshakeParticipant(fixture.member.id, randomNonce(), fixture.memberOffer.capabilities),
                    fixture.anchor, fixture.proof)
                fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture, altered)); flush() }
                assertFalse(owner.readChunk())
                assertTrue(fixture.clientSocket.isClosed)
                assertNull(owner.comparison())
            }
        }
    }

    @Test
    fun cancelBlockAndLeaveInvalidateTicketsAndKeepFirstReason() {
        val events: List<Pair<(GroupAdmissionConnection) -> Unit, GroupAdmissionConfirmationFailure>> = listOf(
            { owner: GroupAdmissionConnection -> owner.close() } to GroupAdmissionConfirmationFailure.Cancelled,
            { owner: GroupAdmissionConnection -> owner.block() } to GroupAdmissionConfirmationFailure.Blocked,
            { owner: GroupAdmissionConnection -> owner.leaveGroup() } to GroupAdmissionConfirmationFailure.LeftGroup,
        )
        for ((event, reason) in events) withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                val ticket = assertNotNull(owner.comparison())
                event(owner)
                assertTrue(fixture.clientSocket.isClosed)
                owner.close()
                owner.block()
                owner.leaveGroup()
                assertClosed(owner, reason)
                assertFalse(owner.confirm(ticket))
                assertFalse(owner.readChunk())
            }
        }
    }

    @Test
    fun cancellationReleasesBlockedTlsReader() = withFixture { fixture ->
        val entered = CountDownLatch(1)
        val transport = WrappedSocket(fixture.clientSocket, input = object : FilterInputStream(fixture.clientSocket.inputStream) {
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                entered.countDown()
                return super.read(bytes, offset, length)
            }
        })
        fixture.clientOwner(socket = transport).use { owner ->
            assertTrue(owner.prepare())
            val reader = Executors.newSingleThreadExecutor()
            try {
                val reading = reader.submit<Boolean> { try { owner.readChunk() } catch (_: IOException) { false } }
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                owner.close()
                assertFalse(reading.get(5, TimeUnit.SECONDS))
                assertTrue(fixture.clientSocket.isClosed)
                assertClosed(owner, GroupAdmissionConfirmationFailure.Cancelled)
            } finally {
                owner.close()
                reader.shutdownNow()
                assertTrue(reader.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun failedFlushCannotAcknowledgeLocalWrite() = withFixture { fixture ->
        val failure = IOException("test-only flush failure")
        val transport = WrappedSocket(fixture.clientSocket, output = object : FilterOutputStream(fixture.clientSocket.outputStream) {
            override fun flush() { throw failure }
        })
        fixture.clientOwner(socket = transport).use { owner ->
            assertTrue(owner.prepare())
            fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture)); flush() }
            assertTrue(owner.readChunk())
            assertSame(failure, assertFailsWith<IOException> { owner.confirm(assertNotNull(owner.comparison())) })
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Transport), owner.state)
            assertTrue(fixture.clientSocket.isClosed)
        }
    }

    @Test
    fun delayedSuccessfulFlushCannotResurrectBlockedAttempt() = withFixture { fixture ->
        val flushing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val transport = WrappedSocket(fixture.clientSocket, output = object : FilterOutputStream(fixture.clientSocket.outputStream) {
            override fun flush() {
                flushing.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
        })
        fixture.clientOwner(socket = transport).use { owner ->
            assertTrue(owner.prepare())
            fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture)); flush() }
            assertTrue(owner.readChunk())
            val writer = Executors.newSingleThreadExecutor()
            try {
                val ticket = assertNotNull(owner.comparison())
                val sending = writer.submit<Boolean> { owner.confirm(ticket) }
                assertTrue(flushing.await(5, TimeUnit.SECONDS))
                assertEquals(active(GroupAdmissionConfirmationState.Sending(true)), owner.state)
                owner.block()
                assertTrue(fixture.clientSocket.isClosed)
                release.countDown()
                assertFalse(sending.get(5, TimeUnit.SECONDS))
                assertClosed(owner, GroupAdmissionConfirmationFailure.Blocked)
            } finally {
                release.countDown()
                owner.close()
                writer.shutdownNow()
                assertTrue(writer.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun deadlineClosesIdleSocketWithoutStateInspectionAndKeepsScheduler() = withFixture { fixture ->
        val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1000
        fixture.clientOwner(selectedAt = selectedAt).use { owner ->
            assertTrue(owner.prepare())
            val expired = CountDownLatch(1)
            fixture.scheduler.schedule({ expired.countDown() }, 1300, TimeUnit.MILLISECONDS)
            assertTrue(expired.await(5, TimeUnit.SECONDS))
            assertTrue(fixture.clientSocket.isClosed)
            assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
            assertFalse(fixture.scheduler.isShutdown)
        }
    }

    @Test
    fun freshConnectionRejectsPriorTicketAndReplay() {
        var previousTicket: GroupAdmissionComparison? = null
        var previousFrame: ByteArray? = null
        var previousDigest: String? = null
        val peers = Peers()
        withFixture(peers) { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                previousTicket = assertNotNull(owner.comparison())
                previousDigest = digest(assertNotNull(previousTicket).bytes)
                previousFrame = remoteFrame(fixture)
            }
        }
        withFixture(peers) { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                assertNotEquals(previousDigest, digest(assertNotNull(owner.comparison()).bytes))
                assertFalse(owner.confirm(assertNotNull(previousTicket)))
                fixture.serverSocket.outputStream.apply { write(assertNotNull(previousFrame)); flush() }
                assertFalse(owner.readChunk())
                assertTrue(fixture.clientSocket.isClosed)
            }
        }
    }

    @Test
    fun clockOrSchedulerFailureClosesTransferredSocket() {
        withFixture { fixture ->
            val failure = AssertionError("test-only clock failure")
            assertSame(failure, assertFailsWith<AssertionError> { fixture.clientOwner(now = { throw failure }) })
            assertTrue(fixture.clientSocket.isClosed)
        }
        withFixture { fixture ->
            fixture.scheduler.shutdown()
            assertFailsWith<RejectedExecutionException> { fixture.clientOwner() }
            assertTrue(fixture.clientSocket.isClosed)
        }
    }

    @Test
    fun selectionDeadlineIsNotRestartedByPrepareOrConfirmation() = withFixture { fixture ->
        var now = 1000L
        fixture.clientOwner(selectedAt = now, now = { now }).use { owner ->
            now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS - 1
            assertTrue(owner.prepare())
            val ticket = assertNotNull(owner.comparison())
            now++
            assertFalse(owner.confirm(ticket))
            assertTrue(fixture.clientSocket.isClosed)
            assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
        }
    }

    @Test
    fun deadlineDuringComparisonInvalidatesTicketAndClosesBeforeReturning() = withFixture { fixture ->
        var calls = 0
        var expireInsideComparison = false
        fixture.clientOwner(selectedAt = 1000, now = {
            if (expireInsideComparison && ++calls >= 2) 1000 + ProtocolHandshakeAttempt.TIMEOUT_MILLIS else 1000
        }).use { owner ->
            assertTrue(owner.prepare())
            expireInsideComparison = true
            assertNull(owner.comparison())
            assertTrue(fixture.clientSocket.isClosed)
            assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
        }
    }

    @Test
    fun confirmedProgressRemainsRevocableByBlockLeaveAndDeadline() {
        val events: List<Pair<(GroupAdmissionConnection) -> Unit, GroupAdmissionConfirmationFailure>> = listOf(
            { owner: GroupAdmissionConnection -> owner.block() } to GroupAdmissionConfirmationFailure.Blocked,
            { owner: GroupAdmissionConnection -> owner.leaveGroup() } to GroupAdmissionConfirmationFailure.LeftGroup,
        )
        for ((event, reason) in events) withFixture { fixture ->
            fixture.clientOwner().use { owner ->
                assertTrue(owner.prepare())
                fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture)); flush() }
                assertTrue(owner.readChunk())
                assertTrue(owner.confirm(assertNotNull(owner.comparison())))
                assertConfirmed(owner)
                event(owner)
                assertTrue(fixture.clientSocket.isClosed)
                assertClosed(owner, reason)
            }
        }
        withFixture { fixture ->
            var now = 1000L
            fixture.clientOwner(selectedAt = now, now = { now }).use { owner ->
                assertTrue(owner.prepare())
                fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture)); flush() }
                assertTrue(owner.readChunk())
                assertTrue(owner.confirm(assertNotNull(owner.comparison())))
                assertConfirmed(owner)
                now += ProtocolHandshakeAttempt.TIMEOUT_MILLIS
                assertNull(owner.comparison())
                assertTrue(fixture.clientSocket.isClosed)
                assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
            }
        }
    }

    @Test
    fun invalidTailCannotPromoteFromValidPrefix() = withFixture { fixture ->
        fixture.clientOwner().use { owner ->
            assertTrue(owner.prepare())
            assertTrue(owner.confirm(assertNotNull(owner.comparison())))
            fixture.serverSocket.outputStream.apply { write(remoteFrame(fixture) + byteArrayOf(0, 0, 0, 0)); flush() }
            assertFailsWith<InvalidGroupAdmissionFrameException> { owner.readChunk() }
            assertTrue(fixture.clientSocket.isClosed)
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.InvalidFrame), owner.state)
        }
    }

    @Test
    fun certificateSnapshotAndAdmissionWorkAreBounded() {
        withFixture { fixture ->
            val tooMany = (1..33).associate { index -> index.toString(16).padStart(64, '0') to fixture.founder.certificate }
            assertFailsWith<IllegalArgumentException> { fixture.clientOwner(certificates = tooMany) }
            assertTrue(fixture.clientSocket.isClosed)
        }
        withFixture { fixture ->
            val certificates = fixture.certificates.toMutableMap()
            fixture.clientOwner(certificates = certificates).use { owner ->
                certificates.clear()
                // The owner keeps the selected snapshot, not a mutable/re-resolved peer map.
                assertTrue(owner.prepare())
                assertNotNull(owner.comparison())
            }
        }
        withFixture { fixture ->
            assertFailsWith<IllegalArgumentException> {
                fixture.clientOwner(certificates = mapOf("alias" to fixture.founder.certificate))
            }
            assertTrue(fixture.clientSocket.isClosed)
        }
    }

    @Test
    fun unexpectedInputFailureOrNoProgressCannotKeepSocketOpen() {
        withFixture { fixture ->
            val failure = java.util.concurrent.CancellationException("test-only input cancellation")
            val transport = WrappedSocket(fixture.clientSocket, input = object : InputStream() {
                override fun read(): Int = throw failure
            })
            fixture.clientOwner(socket = transport).use { owner ->
                assertTrue(owner.prepare())
                assertSame(failure, assertFailsWith<java.util.concurrent.CancellationException> { owner.readChunk() })
                assertTrue(fixture.clientSocket.isClosed)
                assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Adapter), owner.state)
            }
        }
        withFixture { fixture ->
            val transport = WrappedSocket(fixture.clientSocket, input = object : InputStream() {
                override fun read(): Int = 0
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int = 0
            })
            fixture.clientOwner(socket = transport).use { owner ->
                assertTrue(owner.prepare())
                assertFailsWith<IOException> { owner.readChunk() }
                assertTrue(fixture.clientSocket.isClosed)
                assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Transport), owner.state)
            }
        }
    }

    @Test
    fun abortFailureStillClosesSocketAndPreservesPrimaryError() = withFixture { fixture ->
        val primary = IOException("test-only read failure")
        val cleanup = IOException("test-only input shutdown failure")
        val transport = object : WrappedSocket(fixture.clientSocket, input = object : InputStream() {
            override fun read(): Int = throw primary
        }) {
            override fun shutdownInput() {
                try {
                    super.shutdownInput()
                } catch (_: javax.net.ssl.SSLException) {
                    // JSSE's expected missing close_notify must not hide the injected failure.
                }
                throw cleanup
            }
        }
        fixture.clientOwner(socket = transport).use { owner ->
            assertTrue(owner.prepare())
            assertSame(primary, assertFailsWith<IOException> { owner.readChunk() })
            assertTrue(fixture.clientSocket.isClosed)
            assertTrue(primary.suppressed.any { it === cleanup })
            assertSame(cleanup, owner.cleanupFailure)
            assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Transport), owner.state)
        }
    }

    @Test
    fun unavailableAbortPolicyAndStreamsCannotLeakTransferredSocket() {
        withFixture { fixture ->
            val failure = IOException("test-only linger failure")
            val transport = object : WrappedSocket(fixture.clientSocket) {
                override fun setSoLinger(on: Boolean, linger: Int) { throw failure }
            }
            assertSame(failure, assertFailsWith<IOException> { fixture.clientOwner(socket = transport) })
            assertTrue(fixture.clientSocket.isClosed)
            assertFalse(fixture.scheduler.isShutdown)
        }
        withFixture { fixture ->
            val failure = IOException("test-only input unavailable")
            val transport = object : WrappedSocket(fixture.clientSocket) {
                override fun getInputStream(): InputStream = throw failure
            }
            assertSame(failure, assertFailsWith<IOException> { fixture.clientOwner(socket = transport) })
            assertTrue(fixture.clientSocket.isClosed)
        }
    }

    @Test
    fun scheduledDeadlineReleasesSilentTlsReader() = withFixture { fixture ->
        val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1000
        fixture.clientOwner(selectedAt = selectedAt).use { owner ->
            assertTrue(owner.prepare())
            assertFailsWith<IOException> { owner.readChunk() }
            assertTrue(fixture.clientSocket.isClosed)
            assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
        }
    }

    @Test
    fun deadlineCleanupFailureRemainsObservableOutsideSchedulerTask() = withFixture { fixture ->
        val failure = IOException("test-only scheduled cleanup failure")
        val transport = object : WrappedSocket(fixture.clientSocket) {
            override fun shutdownInput() {
                try { super.shutdownInput() } catch (_: javax.net.ssl.SSLException) { }
                throw failure
            }
        }
        val selectedAt = monotonicMillis() - ProtocolHandshakeAttempt.TIMEOUT_MILLIS + 1000
        fixture.clientOwner(socket = transport, selectedAt = selectedAt).use { owner ->
            val afterDeadline = CountDownLatch(1)
            fixture.scheduler.schedule({ afterDeadline.countDown() }, 1300, TimeUnit.MILLISECONDS)
            assertTrue(afterDeadline.await(5, TimeUnit.SECONDS))
            assertTrue(fixture.clientSocket.isClosed)
            assertSame(failure, owner.cleanupFailure)
            assertClosed(owner, GroupAdmissionConfirmationFailure.Expired)
            assertFalse(fixture.scheduler.isShutdown)
        }
    }

    private fun active(state: GroupAdmissionConfirmationState) = GroupAdmissionBridgeState.Active(state)
    private fun assertConfirmed(owner: GroupAdmissionConnection) = assertEquals(active(GroupAdmissionConfirmationState.Confirmed), owner.state)
    private fun assertClosed(owner: GroupAdmissionConnection, reason: GroupAdmissionConfirmationFailure) =
        assertEquals(GroupAdmissionBridgeState.Closed(GroupAdmissionBridgeFailure.Attempt(reason)), owner.state)
    private fun monotonicMillis() = System.nanoTime() / 1_000_000
    private fun framed(bytes: ByteArray) = byteArrayOf(0, 0, (bytes.size shr 8).toByte(), bytes.size.toByte()) + bytes
    private fun remoteFrame(fixture: Fixture, context: GroupAdmissionConfirmationContext = fixture.context) =
        GroupAdmissionConfirmationFrameDecoder.encode(GroupAdmissionConfirmation(fixture.member.id, fixture.issuer.id,
            fixture.member.sign(context.approvalBytes(fixture.member.id))))

    private class Peers {
        val founder = createDesktopIdentity().identity()
        val issuer = createDesktopIdentity().identity()
        val member = createDesktopIdentity().identity()
        val anchor = GroupTrustAnchor(randomNonce(), founder.id)
        val proof = GroupAdmissionProof(anchor, listOf(admission(founder, issuer), admission(issuer, member)))
        private fun admission(issuer: Identity, member: Identity): SignedGroupAdmission {
            val claim = GroupAdmissionClaim(anchor.groupId, issuer.id, member.id)
            return SignedGroupAdmission(claim, issuer.sign(GroupAdmissionCodec.signedBytes(claim)))
        }
    }

    private inner class Fixture(
        val clientSocket: SSLSocket, val serverSocket: SSLSocket, val peers: Peers,
        val selectedAt: Long, val scheduler: ScheduledExecutorService,
    ) {
        val founder get() = peers.founder
        val issuer get() = peers.issuer
        val member get() = peers.member
        val anchor get() = peers.anchor
        val proof get() = peers.proof
        val certificates = mapOf(founder.id to founder.certificate)
        private val capabilities = ProtocolCapabilities(1, setOf("text"), setOf("text"))
        val issuerOffer = ProtocolHandshakeParticipant(issuer.id, randomNonce(), capabilities)
        val memberOffer = ProtocolHandshakeParticipant(member.id, randomNonce(), capabilities)
        val context: GroupAdmissionConfirmationContext

        init {
            // Offers really cross the pinned TLS connection. No live bootstrap owner/timer handover.
            val client = HandshakeV1FrameStream(clientSocket.inputStream, clientSocket.outputStream)
            val server = HandshakeV1FrameStream(serverSocket.inputStream, serverSocket.outputStream)
            client.write(ProtocolHandshakeFrame.Hello(issuerOffer))
            server.write(ProtocolHandshakeFrame.Hello(memberOffer))
            val receivedMember = (client.read() as ProtocolHandshakeFrame.Hello).participant
            val receivedIssuer = (server.read() as ProtocolHandshakeFrame.Hello).participant
            assertEquals(member.id, receivedMember.identity)
            assertEquals(memberOffer.nonce, receivedMember.nonce)
            assertEquals(issuer.id, receivedIssuer.identity)
            assertEquals(issuerOffer.nonce, receivedIssuer.nonce)
            for (received in listOf(receivedMember, receivedIssuer)) {
                assertEquals(capabilities.version, received.capabilities.version)
                assertEquals(capabilities.supportedFeatures, received.capabilities.supportedFeatures)
                assertEquals(capabilities.requiredFeatures, received.capabilities.requiredFeatures)
            }
            context = GroupAdmissionConfirmationContext(receivedIssuer, receivedMember, anchor, proof)
        }

        fun clientOwner(socket: SSLSocket = clientSocket, certificates: Map<String, X509Certificate> = this.certificates,
            selectedAt: Long = this.selectedAt, now: () -> Long = ::monotonicMillis) =
            GroupAdmissionConnection.adopt(socket, issuer, context, certificates, member.id, selectedAt, scheduler, now)
        fun serverOwner(certificates: Map<String, X509Certificate> = this.certificates) =
            GroupAdmissionConnection.adopt(serverSocket, member, context, certificates, issuer.id, selectedAt, scheduler)
    }

    private fun withFixture(peers: Peers = Peers(), block: (Fixture) -> Unit) {
        val selectedAt = monotonicMillis()
        val loopback = InetAddress.getLoopbackAddress()
        val scheduler = Executors.newSingleThreadScheduledExecutor()
        val listener = peers.member.context { it == peers.issuer.id }.serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
        listener.use {
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.soTimeout = 5000
            try {
                val accepting = scheduler.submit<SSLSocket> {
                    val socket = listener.accept() as SSLSocket
                    try {
                        socket.soTimeout = 5000
                        socket.tcpNoDelay = true
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        socket.startHandshake()
                        socket
                    } catch (error: Throwable) {
                        socket.close()
                        throw error
                    }
                }
                (peers.issuer.context { it == peers.member.id }.socketFactory.createSocket(loopback, listener.localPort) as SSLSocket).use { client ->
                    client.soTimeout = 5000
                    client.tcpNoDelay = true
                    client.enabledProtocols = arrayOf("TLSv1.3")
                    client.startHandshake()
                    accepting.get(5, TimeUnit.SECONDS).use { server ->
                        block(Fixture(client, server, peers, selectedAt, scheduler))
                    }
                }
            } finally {
                listener.close()
                scheduler.shutdownNow()
                assertTrue(scheduler.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    /** Only test I/O hooks are replaced; TLS session, keys, abort and streams remain real. */
    private open class WrappedSocket(private val delegate: SSLSocket,
        private val input: InputStream = delegate.inputStream,
        private val output: OutputStream = delegate.outputStream,
    ) : SSLSocket() {
        override fun getInputStream() = input
        override fun getOutputStream() = output
        override fun getSession() = delegate.session
        override fun setSoLinger(on: Boolean, linger: Int) = delegate.setSoLinger(on, linger)
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun isClosed() = delegate.isClosed
        override fun shutdownInput() = delegate.shutdownInput()
        override fun close() = delegate.close()
        override fun getSupportedCipherSuites() = delegate.supportedCipherSuites
        override fun getEnabledCipherSuites() = delegate.enabledCipherSuites
        override fun setEnabledCipherSuites(suites: Array<out String>) { delegate.enabledCipherSuites = suites }
        override fun getSupportedProtocols() = delegate.supportedProtocols
        override fun getEnabledProtocols() = delegate.enabledProtocols
        override fun setEnabledProtocols(protocols: Array<out String>) { delegate.enabledProtocols = protocols }
        override fun addHandshakeCompletedListener(listener: HandshakeCompletedListener) = delegate.addHandshakeCompletedListener(listener)
        override fun removeHandshakeCompletedListener(listener: HandshakeCompletedListener) = delegate.removeHandshakeCompletedListener(listener)
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
}
