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
import androidx.compose.runtime.LaunchedEffect
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
import lantern.domain.LocalGroupController
import lantern.domain.LocalGroupFailure
import lantern.domain.LocalGroupState
import lantern.domain.GroupAdmissionController
import lantern.domain.GroupAdmissionFailure
import lantern.domain.GroupAdmissionRole
import lantern.domain.GroupAdmissionState
import lantern.domain.GroupMembershipController
import lantern.domain.GroupMembershipCheckState
import lantern.domain.GroupSessionController
import lantern.domain.GroupSessionState
import lantern.domain.GroupTextController
import lantern.domain.GroupTextState
import lantern.domain.GroupTextFailure
import lantern.domain.GroupRosterController
import lantern.domain.GroupRosterTextController
import lantern.domain.GroupRosterState
import lantern.domain.GroupRosterFailure
import lantern.domain.SignedGroupText

@Composable
fun LanternApp(controller: DeviceController, localGroup: LocalGroupController? = null) {
    val state by controller.state.collectAsState()
    val admission = controller as? GroupAdmissionController
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
                if (localGroup != null) LocalGroupPanel(localGroup)
                if (admission != null) GroupAdmissionPanel(admission, localGroup)
                if (admission is GroupMembershipController) GroupMembershipCheckPanel(admission)
                if (admission is GroupSessionController) GroupSessionPanel(admission)
                if (controller is GroupTextController && state.active) GroupTextPanel(controller, state.peers)
                if (controller is GroupRosterController && state.active) GroupRosterPanel(controller, state.peers)
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
                    if (admission != null && state.active) {
                        OutlinedButton(onClick = { admission.selectGroupPeer(peer) }) {
                            Text("Ingresso gruppo con ${peer.name}")
                        }
                        if (admission is GroupMembershipController) {
                            OutlinedButton(onClick = { admission.verifyGroupPeer(peer) }) { Text("Verifica membro ${peer.name}") }
                        }
                        if (admission is GroupSessionController) {
                            OutlinedButton(onClick = { admission.negotiateGroupSession(peer) }) {
                                Text("Negozia sessione con ${peer.name}")
                            }
                        }
                    }
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
internal fun GroupRosterPanel(controller: GroupRosterController, peers: List<Peer>) {
    val state by controller.groupRosterState.collectAsState()
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Partecipanti della sessione", style = MaterialTheme.typography.titleMedium)
            Text("Sincronizza su entrambi i dispositivi (120 s). Prove firmate, non stato online o ricevute. Non usa la cronologia.")
            for (peer in peers) OutlinedButton(onClick = { controller.synchronizeGroupRoster(peer) }) {
                Text("Sincronizza roster con ${peer.name}")
            }
            when (val current = state) {
                GroupRosterState.Idle -> Unit
                is GroupRosterState.Synchronizing -> Text("In attesa di ${current.peer.name}: scegli Sincronizza roster anche lì.")
                is GroupRosterState.Synchronized -> SelectionContainer {
                    Column {
                        Text("Roster verificato localmente: ${current.participants.size} partecipanti")
                        Text("Sessione: ${current.sessionId}")
                        for (id in current.participants) Text(id)
                    }
                }
                is GroupRosterState.Failed -> Text(when (current.reason) {
                    GroupRosterFailure.UNAVAILABLE -> "Appartenenza locale non disponibile/verificabile."
                    GroupRosterFailure.SESSION_CHOICE_REQUIRED -> "Più sessioni utilizzate: serve una scelta esplicita."
                    GroupRosterFailure.MISSING_PARTICIPANTS -> "Mancano prove firmate di partecipanti già noti. Sincronizza prima con loro; non vengono omessi."
                    GroupRosterFailure.FAILED -> "Sincronizzazione interrotta, incompatibile, prove non valide o budget superato. Roster precedente preservato."
                })
            }
            Text("Conserva i partecipanti offline. Il testo iniziale fra due rifiuta roster più ampi: invio multipartecipante e recupero restano da integrare.")
            if (state != GroupRosterState.Idle) TextButton(onClick = controller::cancelGroup) { Text("Chiudi roster") }
        }
    }
}

@Composable
internal fun GroupTextPanel(controller: GroupTextController, peers: List<Peer>) {
    val state by controller.groupTextState.collectAsState()
    var body by remember { mutableStateOf("") }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Testo di gruppo · consegna esplicita", style = MaterialTheme.typography.titleMedium)
            Text("Gruppo già ammesso richiesto. Su un dispositivo scegli Invia, sull'altro Ricevi (120 s). Non usa l'associazione PoC.")
            OutlinedTextField(body, { body = it }, Modifier.fillMaxWidth(), label = { Text("Testo di gruppo (massimo 8192 byte)") })
            if (controller is GroupRosterTextController) {
                RosterTextActions(controller, peers, body)
                Text("Percorso iniziale a due dispositivi, disponibile anche su iPhone:")
            }
            for (peer in peers) {
                OutlinedButton(onClick = { controller.sendGroupText(peer, body) }, enabled = ContentLimits.isValidText(body)) {
                    Text("Invia testo gruppo a ${peer.name}")
                }
                OutlinedButton(onClick = { controller.receiveGroupText(peer) }) { Text("Ricevi testo gruppo da ${peer.name}") }
            }
            when (val current = state) {
                GroupTextState.Idle -> Unit
                is GroupTextState.Waiting -> Text("In attesa di ${current.peer.name}: scegli ${if (current.sending) "Ricevi" else "Invia"} sull'altro dispositivo.")
                is GroupTextState.Transferring -> Text("Sessione verificata, trasferimento con ${current.peer.name}…")
                is GroupTextState.Sent -> {
                    Text("Salvato sul destinatario ${current.peer.name}.")
                    GroupTextResult(current.message)
                }
                is GroupTextState.Received -> {
                    Text("Salvato localmente da ${current.peer.name}.")
                    GroupTextResult(current.message)
                }
                is GroupTextState.Failed -> {
                    Text(when (current.reason) {
                        GroupTextFailure.UNAVAILABLE -> "Gruppo o archivio non disponibile/verificabile."
                        GroupTextFailure.ROSTER_REQUIRED -> "Snapshot dei partecipanti mancante o incompatibile: nessun destinatario può essere omesso."
                        GroupTextFailure.SESSION_CHOICE_REQUIRED -> "Più sessioni utilizzate: serve una scelta esplicita."
                        GroupTextFailure.FAILED -> "Trasferimento interrotto o incompatibile; nessuna ricezione remota confermata."
                    })
                    current.attemptedMessageId?.let { id ->
                        SelectionContainer { Text("Tentativo $id: una copia locale potrebbe essere salvata. Nessuna ritrasmissione automatica.") }
                    }
                }
            }
            Text("Percorso iniziale esplicito, non chat multipartecipante completa o recupero. Stop elimina la sessione attiva, non la storia salvata.")
            if (state != GroupTextState.Idle) TextButton(onClick = controller::cancelGroup) { Text("Chiudi trasferimento gruppo") }
        }
    }
}

@Composable
private fun RosterTextActions(controller: GroupRosterTextController, peers: List<Peer>, body: String) {
    val last by controller.lastRosterTextDelivery.collectAsState()
    var messageId by remember { mutableStateOf("") }
    LaunchedEffect(last?.message?.content?.id) { last?.let { messageId = it.message.content.id } }
    Text("Il testo include tutti i partecipanti noti della sessione, anche offline. Ogni scelta consegna al solo dispositivo indicato.")
    for (peer in peers) {
        OutlinedButton(onClick = { controller.sendRosterText(peer, body) }, enabled = ContentLimits.isValidText(body)) {
            Text("Nuovo testo a ${peer.name}")
        }
        OutlinedButton(onClick = { controller.receiveRosterText(peer) }) { Text("Ricevi da ${peer.name}") }
    }
    last?.let { saved ->
        Text("Ultima copia: ${saved.message.content.id}")
        Text("Salvata su ${saved.receivedBy.size}/${saved.message.content.recipients.size} dispositivi, incluso il mittente.")
        for (id in saved.message.content.recipients) {
            Text("${peers.firstOrNull { it.id == id }?.name ?: id}: ${if (id in saved.receivedBy) "salvato" else "ricevuta mancante"}")
        }
    }
    OutlinedTextField(messageId, { messageId = it.trim() }, Modifier.fillMaxWidth(),
        label = { Text("ID copia già salvata da questo mittente") })
    Text("Per consegnare la stessa copia a un altro destinatario, usa il suo ID e scegli Ricevi sull'altro dispositivo. Servono stessa sessione attiva e stessi partecipanti; la storia non riattiva una sessione.")
    for (peer in peers) {
        OutlinedButton(onClick = { controller.deliverRosterText(peer, messageId) }, enabled = messageId.isNotBlank()) {
            Text("Consegna copia a ${peer.name}")
        }
    }
}

@Composable
private fun GroupTextResult(message: SignedGroupText) {
    SelectionContainer {
        Column {
            Text(message.content.body)
            Text("Sessione: ${message.content.sessionId}")
            Text("Messaggio: ${message.content.id}")
        }
    }
}

@Composable
internal fun GroupSessionPanel(controller: GroupSessionController) {
    val state by controller.groupSessionState.collectAsState()
    if (state == GroupSessionState.Idle) return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Negoziazione sessione LAN", style = MaterialTheme.typography.titleMedium)
            when (val current = state) {
                GroupSessionState.Idle -> Unit
                is GroupSessionState.Negotiating -> Text("Seleziona Negozia sessione anche su ${current.peer.name} (120 s). L'appartenenza viene verificata su questo TLS.")
                is GroupSessionState.Selected -> SelectionContainer { Text("Sessione selezionata localmente: ${current.session.sessionId}") }
                is GroupSessionState.NeedsChoice -> Text("Sessioni già utilizzate: serve una scelta esplicita. Nessuna fusione automatica.")
                is GroupSessionState.Failed -> Text("Negoziazione non riuscita o interrotta. Nessun trust o dato persistente modificato.")
            }
            Text("Prima negoziazione esplicita. Nessuna chat, riconnessione o conferma dell'esito remoto. Lo stop del servizio elimina la sessione in memoria, non il gruppo.")
            TextButton(onClick = controller::cancelGroup) { Text("Chiudi negoziazione") }
        }
    }
}

@Composable
internal fun LocalGroupPanel(controller: LocalGroupController) {
    val state by controller.state.collectAsState()
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Gruppo locale", style = MaterialTheme.typography.titleMedium)
            when (val current = state) {
                LocalGroupState.Loading -> Text("Lettura del gruppo salvato…")
                LocalGroupState.Empty -> {
                    Text("Nessun gruppo locale salvato.")
                    Button(onClick = controller::create) { Text("Crea gruppo locale") }
                }
                LocalGroupState.Creating -> Text("Salvataggio del gruppo…")
                is LocalGroupState.Founded -> SelectionContainer { Text("Gruppo: ${current.anchor.groupId}") }
                is LocalGroupState.Adopted -> SelectionContainer { Text("Membro del gruppo: ${current.anchor.groupId}") }
                is LocalGroupState.Failed -> {
                    Text(when (current.reason) {
                        LocalGroupFailure.STORAGE -> "Impossibile leggere o salvare il gruppo. Nessun nuovo tentativo automatico."
                        LocalGroupFailure.INVALID_ROOT -> "Dati del gruppo non validi. Nessun dato è stato sostituito."
                        LocalGroupFailure.IDENTITY_MISMATCH -> "Il gruppo salvato appartiene a un'altra identità. Nessun dato è stato sostituito."
                    })
                    OutlinedButton(onClick = controller::reload) { Text("Rileggi stato salvato") }
                }
                LocalGroupState.Closed -> Text("Gestione gruppo arrestata.")
            }
            Text("Lo stato locale non abilita sessioni o messaggi di gruppo. La creazione non associa dispositivi.")
        }
    }
}

@Composable
internal fun GroupMembershipCheckPanel(controller: GroupMembershipController) {
    val state by controller.membershipCheckState.collectAsState()
    if (state == GroupMembershipCheckState.Idle) return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Verifica appartenenza", style = MaterialTheme.typography.titleMedium)
            when (val current = state) {
                GroupMembershipCheckState.Idle -> Unit
                is GroupMembershipCheckState.Checking -> Text("Seleziona Verifica membro anche su ${current.peer.name} (120 s). Non è un nuovo invito.")
                is GroupMembershipCheckState.Verified -> Text("Questo dispositivo ha verificato ${current.peer.name} nel gruppo ${current.groupId}. Il canale di prova viene chiuso: nessuna sessione o chat abilitata, nessuna conferma dell'esito remoto.")
                is GroupMembershipCheckState.Failed -> Text(if (current.reason == GroupAdmissionFailure.UNAVAILABLE)
                    "Serve un'appartenenza locale salvata e verificabile. Nessun dato modificato."
                else "Verifica fallita o interrotta: gruppo diverso, prova non valida o percorso non supportato. Nessun peer autorizzato.")
            }
            TextButton(onClick = controller::cancelGroup) { Text("Chiudi verifica") }
        }
    }
}

@Composable
internal fun GroupAdmissionPanel(controller: GroupAdmissionController, localGroup: LocalGroupController?) {
    val state by controller.admissionState.collectAsState()
    val membershipRevision by controller.membershipRevision.collectAsState()
    LaunchedEffect(membershipRevision) {
        if (membershipRevision > 0) localGroup?.refreshMembership()
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Ammissione gruppo", style = MaterialTheme.typography.titleMedium)
            when (val current = state) {
                GroupAdmissionState.Idle -> Text("Un membro del gruppo può invitare un dispositivo senza gruppo. Selezionate Ingresso gruppo sui due dispositivi e confrontate il codice completo; il fondatore non deve essere online.")
                is GroupAdmissionState.Selecting -> Text("Seleziona Ingresso gruppo anche su ${current.peer.name} (120 s).")
                is GroupAdmissionState.Comparing -> {
                    Text(if (current.role == GroupAdmissionRole.ISSUER) "Autorizza il nuovo membro" else "Ingresso nel gruppo candidato")
                    SelectionContainer { Text("Gruppo: ${current.groupId}\nCodice completo: ${current.code}") }
                    Text("Confronta TUTTO il codice sui due schermi. Conferma soltanto se coincide.")
                    Button(onClick = { controller.confirmGroup(current) }) { Text("Codice identico: confermo") }
                }
                is GroupAdmissionState.AwaitingPeer -> Text("Conferma inviata. In attesa di ${current.peer.name}…")
                is GroupAdmissionState.Completed -> Text(if (current.adoptedLocally)
                    "Appartenenza salvata su questo dispositivo: ${current.groupId}"
                else "Due conferme verificate. Il salvataggio sul nuovo membro NON è attestato da questo schermo.")
                is GroupAdmissionState.Failed -> {
                    Text(when (current.reason) {
                        GroupAdmissionFailure.UNAVAILABLE -> "Ammissione non disponibile: servono un'appartenenza verificabile oppure un dispositivo senza gruppo e un archivio leggibile."
                        GroupAdmissionFailure.INTERRUPTED -> "Tentativo interrotto conservato. Serve un nuovo confronto; nessun consenso sarà ripreso."
                        GroupAdmissionFailure.COMMIT_OUTCOME_UNKNOWN -> "Esito del salvataggio incerto. Rilettura dello stato locale, nessun replay automatico."
                        GroupAdmissionFailure.FAILED -> "Ammissione interrotta o non valida. Riprova con una nuova selezione su entrambi."
                    })
                    if (current.reason == GroupAdmissionFailure.INTERRUPTED) {
                        OutlinedButton(onClick = { controller.selectGroupPeer(current.peer, replaceInterrupted = true) }) {
                            Text("Nuovo confronto e sostituzione del tentativo interrotto")
                        }
                    }
                }
            }
            if (state != GroupAdmissionState.Idle) {
                TextButton(onClick = controller::cancelGroup) { Text("Chiudi ammissione (non elimina il gruppo)") }
            }
            Text("Percorso distinto dall'associazione PoC; non abilita chat o sessioni di gruppo.")
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
