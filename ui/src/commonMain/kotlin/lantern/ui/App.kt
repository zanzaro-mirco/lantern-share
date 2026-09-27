package lantern.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import lantern.domain.ChatLine
import lantern.domain.ContentLimits
import lantern.domain.DeviceController
import lantern.domain.DeviceState
import lantern.domain.Peer

@Composable
fun LanternApp(controller: DeviceController) {
    val state by controller.state.collectAsState()
    var recipient by remember { mutableStateOf<String?>(null) }

    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(
                Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text("Lantern · prova tecnica LAN", style = MaterialTheme.typography.headlineSmall)
                Text("Protocollo sperimentale · associazione tra due dispositivi")
                DeviceSetup(
                    state = state,
                    onStart = { controller.rename(it); controller.start() },
                    onStop = controller::stop,
                )
                SelectionContainer { Text("Identità: ${state.id}") }
                Text(state.status)
                PairingPanel(state.pairingPeer, state.comparisonCode, controller::confirm, controller::reject)
                Text("Dispositivi scoperti", style = MaterialTheme.typography.titleLarge)
                if (state.peers.isEmpty()) Text("Nessun dispositivo. Verifica rete locale e firewall.")
                state.peers.forEach { peer ->
                    PeerCard(
                        peer = peer,
                        trusted = peer.id in state.trusted,
                        connected = peer.id in state.connected,
                        selected = peer.id == recipient,
                        onPair = { controller.pair(peer) },
                        onSelect = { recipient = peer.id },
                        onBlock = { controller.block(peer.id) },
                    )
                }
                MessageComposer(
                    canSend = recipient in state.connected,
                    onSend = { text -> recipient?.let { controller.send(it, text) } },
                )
                MessageHistory(state.id, state.messages)
                Text("Autorizzati: ${state.trusted.size}. Cronologia locale: ultimi 200 messaggi. Nessun recupero automatico in questa prova.")
            }
        }
    }
}

@Composable
private fun DeviceSetup(state: DeviceState, onStart: (String) -> Unit, onStop: () -> Unit) {
    var name by remember(state.name) { mutableStateOf(state.name) }
    OutlinedTextField(
        value = name,
        onValueChange = { name = it },
        label = { Text("Nome dispositivo") },
        enabled = !state.active,
        singleLine = true,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(onClick = { onStart(name) }, enabled = !state.active && ContentLimits.isValidName(name)) {
            Text("Attiva servizio")
        }
        OutlinedButton(onClick = onStop, enabled = state.active) { Text("Arresta") }
    }
}

@Composable
private fun PairingPanel(peerId: String?, code: String?, onConfirm: () -> Unit, onReject: () -> Unit) {
    if (peerId == null) return
    if (code == null) {
        TextButton(onClick = onReject) { Text("Annulla associazione") }
        return
    }
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Confronta ogni gruppo di cifre sui due dispositivi")
            SelectionContainer { Text(code, style = MaterialTheme.typography.titleMedium) }
            Row {
                Button(onClick = onConfirm) { Text("I codici coincidono") }
                TextButton(onClick = onReject) { Text("Rifiuta") }
            }
        }
    }
}

@Composable
private fun PeerCard(
    peer: Peer,
    trusted: Boolean,
    connected: Boolean,
    selected: Boolean,
    onPair: () -> Unit,
    onSelect: () -> Unit,
    onBlock: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("${peer.name} · ${peer.id.take(12)} · ${peer.host}:${peer.port}")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!trusted) Button(onClick = onPair) { Text("Associa") }
                if (connected) Button(onClick = onSelect) {
                    Text(if (selected) "Destinatario selezionato" else "Scrivi")
                }
                if (trusted) TextButton(onClick = onBlock) { Text("Blocca localmente") }
            }
        }
    }
}

@Composable
private fun MessageComposer(canSend: Boolean, onSend: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Text("Testo cifrato", style = MaterialTheme.typography.titleLarge)
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text("Messaggio (massimo ${ContentLimits.TEXT_BYTES} byte)") },
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        onClick = { onSend(text); text = "" },
        enabled = canSend && ContentLimits.isValidText(text),
    ) { Text("Invia") }
}

@Composable
private fun MessageHistory(localId: String, messages: List<ChatLine>) {
    messages.takeLast(100).forEach { line ->
        val author = if (line.sender == localId) "Tu" else line.sender.take(12)
        val receipt = if (line.received) " ✓ salvato" else ""
        SelectionContainer { Text("$author: ${line.text}$receipt") }
    }
}
