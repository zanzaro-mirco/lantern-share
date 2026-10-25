# ADR 014 — negoziazione iniziale di sessione sul TLS vivo

> **Stato riconciliato al 25 ottobre 2026:** B5 integrato Node/Bonjour/UI e verificato anche Apple c938980 / 175 XCTest complessivi. La singola sessione vive nella run, non nella storia; scelta operativa fra sessioni usate, reconnect e gestione completa rimangono aperti. B7–B8 non eliminano questi limiti. [Evidenze correnti](../STATO_SVILUPPO.md); [indice documentale](STATO_DOCUMENTAZIONE.md). Date, conteggi e “prossimi passi” originari sotto conservano il loro ambito storico.

Data: 21 ottobre 2026; integrazione iOS del 23 ottobre. Blocco B5.

## Risultato e confini

L'azione esplicita **Negozia sessione** su entrambi i Node confronta lo stato della
sessione LAN corrente dopo una nuova verifica delle appartenenze sullo stesso TLS.
Il pannello mostra la decisione locale. Non legge la cronologia, non scrive SQLite,
non concede trust PoC e non attiva chat, recupero, riconnessione o traffico di gruppo.
Il trasporto termina dopo lo scambio: la decisione non è un handle di autorizzazione
riusabile né una conferma del risultato remoto.

Si tratta del primo percorso esplicito fra due partecipanti, non della gestione
completa delle sessioni: snapshot multipartecipante aggiornati, cambio rete
automatico, scelta operativa fra sessioni usate e ciclo di vita del futuro canale
applicativo restano aperti. Nessuna restrizione aggiunta ai requisiti del prodotto.

## Regole condivise

`GroupSessionOffer` distingue una sessione mantenuta dal servizio da una proposta
casuale nuova, non ancora stabilita. Entrambe sono osservazioni non attendibili
prima dei controlli di trasporto/appartenenza.

- Una proposta nuova non può essere già utilizzata.
- Se almeno uno mantiene una sessione, le proposte nuove sono soltanto fallback:
  un dispositivo che rientra raggiunge la sessione rimasta, anche quando vuota.
- Se nessuno mantiene una sessione, le due proposte casuali vuote convergono.
- Il core riusa `SessionSelector`: minimo deterministico fra vuote, precedenza
  dell'unica usata, scelta esplicita fra più usate, conflitti rifiutati.
- Nessun reset di `used` da pulizia della cronologia. Questo blocco non produce
  contenuti e crea soltanto sessioni vuote; il futuro writer dovrà rendere `used`
  monotono prima di pubblicare contenuti, senza aggirare la scelta richiesta.

Il Node conserva una sola sessione in memoria, associata a radice e marker completo
esatto dell'appartenenza. Una nuova negoziazione fallita non la sostituisce. La
chiusura del pannello annulla la selezione, non il gruppo o la sessione mantenuta.
`Node.stop` elimina sempre la sessione; una nuova attivazione non la ricava dal
database, da SSID/IP, dagli annunci o dalla cronologia. Se l'altro resta attivo,
quello che rientra può raggiungerne la sessione. Se entrambi si arrestano, una nuova
negoziazione genera nuovi ID. Il cambio LAN richiede ancora stop/riavvio esplicito.

## Compatibilità e formato

Entrambi gli HELLO devono supportare E richiedere **group-membership-check** e
**group-session-selection**. I vecchi peer e il solo percorso B4 rifiutano la
continuazione per incompatibilità; nessuno sniffing o fallback. B4 e i formati
precedenti rimangono identici. Nessuna migrazione schema, versione dipendenze,
lock o modifica dei workflow.

Dopo il consueto scambio membership LGM, ogni destinatario verifica la prova con
radice locale indipendente e pin TLS effettivo PRIMA di leggere/scrivere offerte
di sessione. Il risultato B4 precedente non viene consultato. Segue un solo frame
uint32 big endian, lunghezza ESATTAMENTE 133 validata prima del payload:

| Offset | Contenuto |
|---|---|
| 0–3 | ASCII `LSN` e byte versione 1 |
| 4–67 | gruppo, 64 byte ASCII hex minuscoli |
| 68–131 | ID sessione, 64 byte ASCII hex minuscoli, casuale a 256 bit |
| 132 | 0 proposta nuova vuota; 2 sessione mantenuta vuota; 3 mantenuta usata |

Altri flag, lunghezze, byte, gruppi diversi, troncamenti e dati ulteriori sono
rifiutati. Il codec è Kotlin comune; non esiste un codec OS distinto.

## Ownership e arbitraggio

`HandshakeV1Connection.negotiateSession` conserva owner, socket, endpoint TLS e
deadline originale di 120 secondi; lo scambio LGM e quello LSN non riarmano timer.
Il pin minore scrive per primo in entrambe le fasi, l'altro legge e poi scrive.
Le letture sono esatte, ogni lettura e le write verificano il lifetime; la verifica
OS avviene senza state lock. Cancel e scadenza interrompono anche I/O bloccato.
I vecchi confronti/APPROVE, altre negoziazioni e il trasferimento all'ammissione
non possono riutilizzare l'owner dopo l'inizio dello scambio.

Il servizio ricontrolla radice, marker esatto, selezione e deadline prima e dopo
la verifica OS e prima di accettare il risultato. La pubblicazione e la sessione
locale sono arbitrate con cancel/stop sotto un lock breve, senza socket, SQLite
o OS sotto quel lock. Callback vecchi non installano sessioni in una nuova run.
L'ultimo writer attende solo EOF entro la stessa deadline per non troncare byte
TLS accodati; EOF non prova l'esito remoto. Lo stop non cancella l'appartenenza.

## Accettazione e prossimo utilizzatore

Test comuni per formato/negoziazione/scelta; test OS mantenuti per framing esatto,
EOF/flush/deadline, owner non riusabile e cancel/scadenza in receive dopo prova
P-256 vera; test Node/TLS/SQLite riaperto in entrambi gli ordinamenti, membri
delegati col fondatore offline, continuità/nuovo ID, gruppi errati e modalità
incompatibili senza trust/commit/storia. Evidenze effettive in STATO, non hardware.

## Ingresso Bonjour/iOS

`IosGroupAdmissionController` espone lo stesso contratto/pannello sessione e una
selezione opaca distinta dall'invito e dal controllo B4. `GroupAdmissionSession`
esegue preflight committato prima del pin e verifica nuovamente sul TLS vivo.
`HandshakeV1Channel.negotiateSession` sceglie la continuazione PRIMA dello scambio
LGM: nessun EOF reader B4 accodato fra LGM e LSN, secondo reader o ritiro prematuro.
Ordine, capability, binding locale alla prova, codec e budget esatti del decoder
sono Kotlin; Swift mantiene soltanto I/O seriale, completamenti contentProcessed,
verificatori OS e timer originale. Nessun byte LSN prima della verifica della prova.

`BonjourProbe` possiede `IosGroupSessionMemory`, non la singola selezione. Conserva
radice/marker esatto/sessione; cancel non la azzera, stopResources e deallocazione
sì. Generazione casuale OS e letture SQL avvengono prima della pubblicazione,
ricontrollata viva e invariata sulla coda seriale. Nessun callback dentro il passo
Kotlin che seleziona e conserva in memoria. Owner ritirati non accedono più al DB;
il drain cumulativo precedente resta responsabile della chiusura SQLite.

Sette nuovi XCTest mantenuti predisposti: servizio con TLS/Keychain/SQLite veri
in entrambi gli ordinamenti, riapertura, continuità/reset, modalità/gruppi errati,
cancel/riselezione, receive LSN pendente dopo prove vere e deadline originale;
regole memoria con marker intero e conflitti. Scenario delegato con fondatore
offline esteso a LSN. Core decoder e presentazione verificati su JVM/Android,
facciate compilate sul controllo host: NON export Native o Swift. Checkpoint Apple
completo necessario; nessun collaudo fisico nuovo o sessione completa dichiarata.

Checkpoint successivo letto da concluso: `c938980`, iOS completo 39923555251 success,
Native/export/app e 175 XCTest senza fallimenti, inclusi i sette nuovi casi.
Bootstrap compilato soltanto. Ingresso B5 verificato automaticamente anche iOS,
non hardware o chat. Il prerequisito durevole successivo è in [ADR 015](ADR-015-TESTO-GRUPPO-DUREVOLE.md).
