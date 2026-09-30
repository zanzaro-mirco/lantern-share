package lantern.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ComposeUIViewController
import lantern.domain.ContentLimits
import lantern.domain.Reconnection
import lantern.persistence.IosDeviceRepository
import lantern.persistence.openIosRepository
import lantern.protocol.Wire
import lantern.protocol.WireFrameDecoder
import lantern.protocol.PairingWire
import lantern.protocol.TextWire
import lantern.protocol.Frame
import platform.UIKit.UIViewController

class IosPersistence private constructor(private val repository: IosDeviceRepository) {
    @Throws(Exception::class)
    fun name(): String = repository.name()

    @Throws(Exception::class)
    fun rename(value: String) {
        require(ContentLimits.isValidName(value)) { "Nome dispositivo non valido" }
        repository.rename(value)
    }
    @Throws(Exception::class)
    fun trusted(): List<String> = repository.trusted().sorted()
    @Throws(Exception::class)
    fun trust(id: String, admission: String) = repository.trust(id, admission)
    @Throws(Exception::class)
    fun block(id: String) = repository.block(id)
    @Throws(Exception::class)
    fun saveMessage(frame: IosPairingFrame): Boolean =
        repository.save(frame.id, frame.sender, frame.session, frame.body, frame.signature)
    @Throws(Exception::class)
    fun history(): List<IosChatLine> = repository.history().map {
        IosChatLine(id = it.id, sender = it.sender, text = it.text, received = it.received)
    }
    @Throws(Exception::class)
    fun acknowledge(id: String) = repository.acknowledge(id)
    fun close() = repository.close()

    companion object {
        fun open(databaseDirectory: String) = IosPersistence(openIosRepository(databaseDirectory))
    }
}

@Throws(Exception::class)
fun openIosPersistence(databaseDirectory: String): IosPersistence = IosPersistence.open(databaseDirectory)

/** Swift-facing boundary: Network.framework moves bytes; Kotlin owns framing and wire validation. */
class IosWireFraming {
    private val decoder = WireFrameDecoder()

    @Throws(Exception::class)
    fun frame(json: String): ByteArray = WireFrameDecoder.encode(Wire.decode(json.encodeToByteArray()))

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): List<String> = decoder.accept(chunk).map { Wire.encode(it).decodeToString() }

    fun reset() = decoder.reset()
}

data class IosPairingFrame(
    val type: String,
    val sender: String,
    val nonce: String,
    val session: String,
    val body: String,
    val signature: String,
    val json: String,
    val id: String,
)

/** Swift-facing channel boundary. Kotlin owns wire-v0 validation and canonical bytes. */
class IosPairingProtocol {
    private val decoder = WireFrameDecoder()

    fun reconnectDelayMillis(attempt: Int, jitter: Double): Long = Reconnection.delayMillis(attempt, jitter)

    @Throws(Exception::class)
    fun hello(sender: String, nonce: String): ByteArray =
        WireFrameDecoder.encode(PairingWire.hello(sender, nonce))

    @Throws(Exception::class)
    fun transcript(localId: String, localNonce: String, remoteId: String, remoteNonce: String): String =
        PairingWire.transcript(localId, localNonce, remoteId, remoteNonce)

    @Throws(Exception::class)
    fun displayCode(session: String): String = PairingWire.displayCode(session)

    @Throws(Exception::class)
    fun approvalSigningBytes(sender: String, peerId: String, session: String): ByteArray =
        Wire.signedBytes(PairingWire.approval(sender, peerId, session))

    @Throws(Exception::class)
    fun approval(sender: String, peerId: String, session: String, signature: String): ByteArray =
        WireFrameDecoder.encode(PairingWire.approval(sender, peerId, session, signature))

    @Throws(Exception::class)
    fun textSigningBytes(sender: String, id: String, session: String, body: String): ByteArray =
        Wire.signedBytes(TextWire.text(sender, id, session, body))

    @Throws(Exception::class)
    fun text(sender: String, id: String, session: String, body: String, signature: String): IosPairingFrame =
        view(TextWire.text(sender, id, session, body, signature))

    @Throws(Exception::class)
    fun frame(json: String): ByteArray = WireFrameDecoder.encode(Wire.decode(json.encodeToByteArray()))

    @Throws(Exception::class)
    fun acknowledgement(sender: String, id: String): ByteArray =
        WireFrameDecoder.encode(TextWire.acknowledgement(sender, id))

    @Throws(Exception::class)
    fun signingBytes(json: String): ByteArray = Wire.signedBytes(Wire.decode(json.encodeToByteArray()))

    @Throws(Exception::class)
    fun accept(chunk: ByteArray): List<IosPairingFrame> = decoder.accept(chunk).map(::view)

    private fun view(frame: Frame): IosPairingFrame =
        IosPairingFrame(
            type = frame.type.name,
            sender = frame.sender,
            nonce = frame.nonce,
            session = frame.session,
            body = frame.body,
            signature = frame.signature,
            json = Wire.encode(frame).decodeToString(),
            id = frame.id,
        )

    fun reset() = decoder.reset()
}

data class IosPeer(val id: String, val name: String)
data class IosChatLine(val id: String, val sender: String, val text: String, val received: Boolean)

/** UI state is updated on the main thread; native I/O stays on the service queue. */
class IosProbeState {
    var identityId by mutableStateOf("")
        private set
    var identityError by mutableStateOf("")
        private set
    var status by mutableStateOf("Scoperta Bonjour arrestata")
        private set
    var deviceName by mutableStateOf("")
        private set
    var persistenceError by mutableStateOf("")
        private set
    var devices by mutableStateOf(listOf<IosPeer>())
        private set
    var trusted by mutableStateOf(listOf<String>())
        private set
    var pairingPeer by mutableStateOf("")
        private set
    var comparisonCode by mutableStateOf("")
        private set
    var connectedPeer by mutableStateOf("")
        private set
    var messages by mutableStateOf(listOf<IosChatLine>())
        private set
    fun updateConnected(peerId: String) { connectedPeer = peerId }
    fun updateMessages(values: List<IosChatLine>) { messages = values }
    fun updateStatus(value: String) { status = value }
    fun updateDevices(values: List<IosPeer>) { devices = values }
    fun updateTrusted(values: List<String>) { trusted = values }
    fun updatePairing(peerId: String, code: String) { pairingPeer = peerId; comparisonCode = code }
    fun updateIdentity(value: String) { identityId = value; identityError = "" }
    fun updateIdentityError(value: String) { identityError = value; identityId = "" }
    fun updateDeviceName(value: String) { deviceName = value; persistenceError = "" }
    fun updatePersistenceError(value: String) { persistenceError = value }
}
fun ProbeViewController(
    state: IosProbeState,
    start: () -> Unit,
    stop: () -> Unit,
    rename: (String) -> Unit,
    pair: (String) -> Unit,
    confirm: () -> Unit,
    reject: () -> Unit,
    send: (String, String) -> Unit,
): UIViewController = ComposeUIViewController {
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Lantern · iPhone", style = MaterialTheme.typography.headlineMedium)
                Text("Associazione LAN e testo cifrato · protocollo sperimentale")
                if (state.identityId.isNotEmpty()) Text("Identità persistente: ${state.identityId}")
                else Text(state.identityError.ifEmpty { "Apertura identità nel Keychain…" })
                var editedName by remember(state.deviceName) { mutableStateOf(state.deviceName) }
                OutlinedTextField(
                    value = editedName,
                    onValueChange = { editedName = it },
                    label = { Text("Nome dispositivo") },
                    singleLine = true,
                    enabled = state.deviceName.isNotEmpty(),
                )
                Button(
                    onClick = { rename(editedName) },
                    enabled = state.deviceName.isNotEmpty() &&
                        editedName != state.deviceName && ContentLimits.isValidName(editedName),
                ) { Text("Salva nome") }
                if (state.persistenceError.isNotEmpty()) Text(state.persistenceError, color = MaterialTheme.colorScheme.error)
                Text("TLS 1.3 con confronto completo del codice. Ricevuta dopo il salvataggio sul destinatario.")
                Row { Button(onClick = start, enabled = state.identityId.isNotEmpty()) { Text("Cerca nella LAN") }; TextButton(onClick = stop) { Text("Arresta") } }
                Text(state.status)
                if (state.pairingPeer.isNotEmpty()) {
                    Text("Dispositivo selezionato: ${state.pairingPeer}")
                    if (state.comparisonCode.isEmpty()) Text("Seleziona lo stesso dispositivo anche sull'altro schermo.")
                    else {
                        Text("Confronta TUTTO il codice:")
                        Text(state.comparisonCode)
                        Row {
                            Button(onClick = confirm) { Text("Conferma") }
                            TextButton(onClick = reject) { Text("Rifiuta") }
                        }
                    }
                }
                state.devices.forEach { peer ->
                    Column {
                        Text("${peer.name} · ${peer.id.take(12)}")
                        if (peer.id in state.trusted) Text("Autorizzato")
                        else Button(onClick = { pair(peer.id) }) { Text("Associa") }
                    }
                }
                Text("Testo cifrato", style = MaterialTheme.typography.titleLarge)
                if (state.connectedPeer.isNotEmpty()) Text("Collegato: ${state.connectedPeer.take(12)}")
                else Text("Associa e collega un dispositivo per inviare.")
                var text by remember { mutableStateOf("") }
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("Messaggio (massimo ${ContentLimits.TEXT_BYTES} byte)") },
                )
                Button(
                    onClick = { send(state.connectedPeer, text); text = "" },
                    enabled = state.connectedPeer.isNotEmpty() && ContentLimits.isValidText(text),
                ) { Text("Invia") }
                state.messages.forEach { line ->
                    val own = line.sender == state.identityId
                    Text("${if (own) "Tu" else line.sender.take(12)}: ${line.text}")
                    if (own) Text(if (line.received) "Salvato sul destinatario ✓" else "Salvato localmente · ricevuta non disponibile")
                }
            }
        }
    }
}
