package lantern.connectivity

import lantern.domain.ContentLimits
import lantern.domain.MessageRepository
import lantern.domain.PeerTransport
import lantern.protocol.Frame
import lantern.protocol.FrameType
import lantern.protocol.Wire
import java.io.Closeable
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLSocket

internal sealed interface ConnectionEvent {
    data class AwaitingComparison(val code: String) : ConnectionEvent
    data object Connected : ConnectionEvent
    data object RepositoryChanged : ConnectionEvent
}

/** Owns one TLS-authenticated socket; no discovery, UI state or SQL driver dependencies. */
internal class PeerConnection(
    private val socket: SSLSocket,
    val remoteId: String,
    private val certificate: X509Certificate,
    private val identity: Identity,
    private val authorization: PairingAuthorization,
    private val messages: MessageRepository,
    private val isActive: () -> Boolean,
    private val onEvent: (ConnectionEvent) -> Unit,
) : PeerTransport, Closeable {
    private val stream = FrameStream(socket.inputStream, socket.outputStream)
    private val pendingAcks = ConcurrentHashMap.newKeySet<String>()
    private val pairingAttempt = authorization.attemptFor(remoteId)
    @Volatile private var session = ""
    @Volatile private var authorized = false
    private var localApproval = false
    private var remoteApproval: Frame? = null

    fun run() {
        exchangeHello()
        while (isActive()) {
            val frame = stream.read()
            require(frame.sender == remoteId && authorization.allowsHandshake(remoteId))
            when (frame.type) {
                FrameType.APPROVE -> receiveApproval(frame)
                FrameType.TEXT -> receiveText(frame)
                FrameType.ACK -> receiveAcknowledgement(frame)
                FrameType.HELLO -> error("HELLO duplicato")
            }
        }
    }

    private fun exchangeHello() {
        val nonce = randomNonce()
        stream.write(Frame(type = FrameType.HELLO, sender = identity.id, nonce = nonce))
        val hello = stream.read()
        require(hello.type == FrameType.HELLO && hello.sender == remoteId)
        session = digest(Wire.transcript(identity.id, nonce, remoteId, hello.nonce).encodeToByteArray())
        authorized = authorization.isTrusted(remoteId)
        if (authorized) {
            socket.soTimeout = 0
            onEvent(ConnectionEvent.Connected)
        } else {
            socket.soTimeout = PAIRING_READ_TIMEOUT_MILLIS
            onEvent(ConnectionEvent.AwaitingComparison(session.chunked(4).joinToString(" ")))
        }
    }

    @Synchronized
    fun approve(displayedCode: String) {
        check(isActive() && pairingAttempt != null && authorization.attemptFor(remoteId) == pairingAttempt)
        check(session.isNotEmpty() && displayedCode == session.chunked(4).joinToString(" "))
        if (localApproval) return
        val approval = sign(Frame(type = FrameType.APPROVE, sender = identity.id, session = session, body = remoteId))
        stream.write(approval)
        localApproval = true
        finishPairing()
    }

    @Synchronized
    private fun receiveApproval(frame: Frame) {
        require(frame.session == session && frame.body == identity.id)
        require(Identity.verify(certificate, Wire.signedBytes(frame), frame.signature))
        remoteApproval = frame
        finishPairing()
    }

    private fun finishPairing() {
        val approval = remoteApproval ?: return
        if (!localApproval || authorized) return
        check(isActive())
        authorization.admit(remoteId, Wire.encode(approval).decodeToString(), checkNotNull(pairingAttempt))
        authorized = true
        socket.soTimeout = 0
        onEvent(ConnectionEvent.RepositoryChanged)
        onEvent(ConnectionEvent.Connected)
    }

    private fun receiveText(frame: Frame) {
        requireAuthorized()
        require(frame.session == session)
        require(Identity.verify(certificate, Wire.signedBytes(frame), frame.signature))
        messages.save(frame.id, frame.sender, frame.session, frame.body, frame.signature)
        onEvent(ConnectionEvent.RepositoryChanged)
        stream.write(Frame(type = FrameType.ACK, sender = identity.id, id = frame.id))
    }

    private fun receiveAcknowledgement(frame: Frame) {
        requireAuthorized()
        require(pendingAcks.remove(frame.id)) { "Ricevuta inattesa" }
        messages.acknowledge(frame.id)
        onEvent(ConnectionEvent.RepositoryChanged)
    }

    fun sendText(text: String) {
        require(ContentLimits.isValidText(text))
        requireAuthorized()
        val frame = sign(Frame(
            type = FrameType.TEXT,
            sender = identity.id,
            id = UUID.randomUUID().toString(),
            session = session,
            body = text,
        ))
        messages.save(frame.id, frame.sender, frame.session, frame.body, frame.signature)
        onEvent(ConnectionEvent.RepositoryChanged)
        pendingAcks.add(frame.id)
        try {
            stream.write(frame)
        } catch (error: Exception) {
            pendingAcks.remove(frame.id)
            throw error
        }
    }

    private fun sign(frame: Frame): Frame = frame.copy(signature = identity.sign(Wire.signedBytes(frame)))

    private fun requireAuthorized() {
        check(isActive() && authorized && authorization.isTrusted(remoteId)) { "Peer non autorizzato" }
    }

    override fun close() = socket.close()

    private companion object {
        const val PAIRING_READ_TIMEOUT_MILLIS = 120_000
    }
}
