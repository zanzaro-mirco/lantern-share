# Dichiarazione di ammissione al gruppo

## Verifica di membri già ammessi — B4

Percorso opzionale distinto dall'invito: [ADR 013](ADR-013-VERIFICA-APPARTENENZA-TLS.md).
Node Android/desktop e azione Verifica membro controllano la prova fino all'identità
del peer mutual-TLS contro il gruppo locale indipendente, senza nuove deleghe o
conferme. Il risultato diagnostico non apre sessioni né promuove trust. Stesso owner,
selezione esclusiva e scadenza; formato nuovo solo previa negoziazione obbligatoria
della feature opzionale, senza cambiare i codec sottostanti. Integrazione iOS ancora
da realizzare, verifiche effettive in STATO, collaudi fisici aperti.

## Inviti da membri già ammessi — 19 ottobre 2026

LocalGroupAdmission è il produttore comune consumato da Node e GroupAdmissionSession.
Il fondatore usa la fondazione locale; un membro adottato deve leggere il marker
COMMITTATO, con radice identica e identità OS corrente. Il produttore verifica catena
completa e due conferme storiche mediante gli adattatori certificati esistenti,
richiede il DER locale esatto del marker, poi aggiunge e verifica la nuova delega
firmata dall'identità OS. Conserva tutte le deleghe/certificati precedenti. Non legge
il journal pendente, non scrive appartenenza, non ripristina consenso o deadline.

Cicli/destinatario già nel percorso e superamento dei 32 elementi preesistenti sono
rifiutati, mai troncati; non si introduce un limite di 32 membri o una nuova revoca.
Radice e marker completo sono riletti dopo la firma, e dagli owner prima dell'invio
e della conferma. Un cambiamento del solo ID operazione invalida comunque la selezione.
Letture e verifiche non promettono atomicità contro scrittori OS/DB esterni: il servizio
resta responsabile della serializzazione lifecycle. Errori OS propagati senza fallback.

Un invito nuovo richiede ancora TLS selezionato, offerte/nonce nuovi, codice completo,
due clic e commit locale A; il vecchio materiale non è un ticket per il nuovo consenso.
Il fondatore non deve essere online. Ruolo UI emittente, non amministratore. Schema,
wire e dipendenze invariati. Test mantenuti A→B→C con store riaperti e fondatore offline;
esiti effettivi in STATO. Verificato anche nel simulatore su a316ca5 / 162 XCTest,
non hardware; il nuovo controllo B4 resta distinto dall'ammissione già verificata.

## Ingresso nel servizio iOS — 19 ottobre 2026

BonjourProbe compone GroupAdmissionSession sulla propria coda seriale non-UI e sul
listener/discovery esistenti. Il pannello Compose condiviso passa tramite
IosGroupAdmissionController: selezioni opache distinte, clic dell'istanza visualizzata,
callback vecchi inerti. I ticket crittografici restano privati al servizio. Questa è
integrazione nell'app, non soltanto una facciata; verificata in simulatore su b0914a9,
161 XCTest senza fallimenti. Deleghe sopra verificate dal checkpoint successivo a316ca5.

Durante la scelta v1 AllowedPeerStore esclude i pin fidati PoC, il reconnect v0 resta
sospeso e il TLS entrante è assegnato alla selezione corrente PRIMA dell'handshake.
Sessioni sostituite chiudono anche i TLS pendenti; nessuno può riusarli nel tentativo nuovo.
Capability/ruoli e ordinamento delle identità sono quelli del Node descritti sotto;
non sono autorità. Retry soltanto prima del bootstrap entro i 120 s originari.

HandshakeV1Channel usa letture evidence bounded esatte anche nel nuovo percorso
receiveRootEvidenceAndTransfer: release a GroupRootAdoptionChannel sulla stessa coda,
connessione/scadenza originarie, nessun I/O precedente ancora pendente al trasferimento.
La radice rimane candidata, non viene passata all'overload che richiede fiducia
indipendente. Verifica proof/endpoint e firme rimane nel core e negli adattatori esistenti.

Due clic e firme verificate precedono handover/commit locale A, accodati fuori dai callback
del medesimo owner. Errori prima del commit distinti dal suo esito incerto terminale;
nessun replay. Sostituzione esplicita del vecchio journal soltanto con identità locale
coerente, snapshot esatto e confronto fresco. Il fondatore non attesta il salvataggio remoto.
Cancel/stop non eliminano un commit già completato. Notifica e rilettura della membership
non dipendono dalla selezione ancora visibile; un refresh durante Loading/Creating è accodato.

Ogni selezione entra nel drain cumulativo del servizio. GroupRootAdoptionChannel rimane
trattenuto fino a whenClosedAndDrained; anche le selezioni già sostituite devono rientrare
prima della chiusura SQLite. Bootstrap/emittente non accedono al DB da callback tardivi
dopo cancel. Nessun trust PoC, sessione o traffico di gruppo deriva dall'appartenenza.
Test servizio Swift mantenuti con TLS/Keychain/SQLite veri; esiti in STATO.
Inviti delegati descritti sopra; collaudi hardware aperti, non cambia la specifica.

## Ingresso nell'app Android/desktop — 19 ottobre 2026

Il pannello tecnico espone «Ingresso gruppo» distinto dal pairing PoC. Il fondatore
crea prima il gruppo; il nuovo membro non deve avere un gruppo. Entrambi selezionano
il peer scoperto. Node sospende il reconnect PoC durante la selezione e ritira i vecchi
socket: il protocollo si sceglie localmente, mai sniffando/facendo fallback da byte remoti.
Ogni handshake TLS cattura il token esatto della selezione; un'altra selezione non può
riusare quel TLS. Pin e scadenza restano quelli della selezione originale (120 s).

Il normale HELLO v1 usa requiredFeatures `["group-admission"]` e supportedFeatures con
`group-admission` più un solo ruolo locale: `group-issuer` oppure `group-candidate`.
Ruoli uguali/ambigui sono rifiutati prima dell'evidence. Sono metadati pubblici per
l'instradamento, NON appartenenza o autorità: radice locale del fondatore, catena,
certificati endpoint, firme e doppia conferma restano obbligatori. Non cambia alcun
campo, codec, formato di prova o versione wire; nessun nuovo frame/ACK distribuito.
Queste capability di servizio vanno riusate nel futuro ingresso Apple.

Il fondatore usa prepareFounderGroupAdmission e l'evidence esistente. Il destinatario
cede il bootstrap direttamente a GroupRootAdoptionConnection, non all'overload con
radice indipendente: la radice ricevuta è candidata e viene legata al confronto completo.
Nessun owner precedente resta attivo, anche se l'inizializzazione del ricevente fallisce.
Il ticket core rimane privato al worker: la UI deve restituire proprio l'istanza mostrata,
non solo lo stesso hash. Non si legge/signa in parallelo mentre si attende il clic locale;
timer e annullamento restano attivi. Dopo write e conferma remota verificate il destinatario
esegue handover e commit locale A; l'emittente non può attestare il salvataggio remoto e
mantiene TLS fino al ritiro/deadline. Nessun trust PoC o traffico di gruppo è abilitato.

Esito SQLite incerto: stato terminale e rilettura della membership, senza replay. Un
pendente già presente richiede la specifica azione «nuovo confronto e sostituzione»:
snapshot esatto trattenuto alla selezione e rimosso solo dopo nuove firme/conferme, non
all'avvio. Cancel/blocco/arresto prima dell'handoff di commit impediscono il salvataggio;
un commit già in corso può completare, non è rollback/uscita dal gruppo.

membershipRevision segnala la rilettura anche dopo la chiusura della selezione durante
il commit. Il pannello richiede una lettura OS/SQLite, non deduce l'appartenenza dal contatore;
LocalGroupService non perde la richiesta arrivata mentre una lettura/creazione era in corso.

Test mantenuti GroupAdmissionServiceTest sul vero Node coprono TLS/P-256/SQLite,
riapertura, consenso mancante/vecchio, ruoli errati, blocco, riprova/esito incerto e ritorno
esplicito al PoC. Esiti effettivi in STATO. Ingresso servizio iOS e inviti da membro
delegato ancora aperti; il fondatore non diventa un amministratore di prodotto.

## Ispezione del candidato depositato — 17 ottobre 2026

`GroupRootAdoptionJournalInspection` controlla uno snapshot senza modificarlo: decode completo, identità OS corrente ↔ metadati ↔ ruoli/radice del payload, intera catena e firme di membro/emittente sui byte canonici ricostruiti. Usa gli stessi certificati esatti dei pin dichiarati; il verificatore OS applica DER, curva, validità, autofirma e firma. Nessuna nuova codifica di rete o migrazione. L'ID tentativo non è autenticato dalle firme storiche.

`HistoricalSignaturesValid` non è consenso corrente, fiducia indipendente nella radice o autorizzazione al commit. Non scavalca un gruppo già fondato, blocco o uscita; questi controlli e l'identità/lifecycle correnti appartengono al futuro owner. L'ispezione non ricostruisce deadline o selezioni TLS e non attiva alcun peer. Payload malformati/versioni ignote restano errori a diagnostica fissa, mai assenza o rimozione automatica; errori inattesi OS e cancellazioni propagano. Dettagli e responsabilità in [ADR 011](ADR-011-JOURNAL-ADOZIONE-LOCALE.md).

Adattatore JVM/Android implementato con i verificatori esistenti, provato con firme P-256, certificati reali e SQLite riaperto. Ponte Kotlin/Swift di sola lettura e sette XCTest predisposti, non verificati localmente su Windows. Nessuna nuova orchestrazione UI/servizio o adozione. Le verifiche del journal precedente `ef3026c` sono riuscite anche nel checkpoint Native/simulatore iOS, ma non coprono il nuovo ponte di questo incremento; risultati correnti in STATO.

## Payload locale del journal — 14 ottobre 2026

`GroupRootAdoptionJournal` conserva materiale **non attendibile**, non uno stato di appartenenza o un ticket di consenso. È limitato al destinatario candidato: offerta locale del nuovo membro, offerta remota dell'ultimo emittente, evidence completa con i certificati di tutti gli emittenti, certificato pubblico del membro e due GROUP_CONFIRM direzionali. Le offerte sono copie difensive. `fromDraft` confronta prova canonica e byte completi del confronto con la bozza rilasciata; non verifica liveness, certificati o firme e non acquisisce ownership del trasporto. I certificati dei veri endpoint devono prevalere sull'evidence ricevuta prima della cattura.

`GroupRootAdoptionJournalCodec` è esclusivamente un formato locale, separato dai frame di rete: header ASCII `LGRJ`, versione binaria `01`, sei campi in ordine fisso, ciascuno preceduto dalla lunghezza unsigned big-endian a quattro byte. Lunghezze controllate prima di conversioni/allocazioni; zero, overflow, troncamenti, byte residui e versioni ignote sono rifiutati. Budget totale **278901 byte**, derivato dai limiti dei codec riusati, non un nuovo limite dei frame.

| Campo | Contenuto | Limite byte |
|---|---|---:|
| 1 | GROUP_EVIDENCE JSON esistente | 262144 |
| 2 | HELLO del membro | 4608 |
| 3 | HELLO dell'emittente | 4608 |
| 4 | DER pubblico del membro, Base64 canonico | 5464 |
| 5 | GROUP_CONFIRM locale | 1024 |
| 6 | GROUP_CONFIRM remoto | 1024 |

Le strutture JSON interne mantengono codec, normalizzazione, controllo duplicati e limiti preesistenti; non sono riparse come mappe che perderebbero campi duplicati. L'identità dichiarata del certificato membro è quella dell'offerta locale; soltanto l'adattatore OS può verificare che il DER produca davvero quel pin. Il contesto firmato viene ricostruito dalla prova e dalle offerte, non da un digest/booleano sostituibile. Non si serializzano clock monotoni, deadline, stato Confirmed, chiavi private o conferme di commit.

**Decode non autorizza nulla:** DER/firme sintatticamente valide, catene incoerenti o un cambio di nonce correttamente codificato possono essere decodificati. Prima di ogni futuro recovery servono policy OS DER/pin/validità, intera catena e entrambe le firme sul contesto ricostruito, identità locale corrente, stato durevole e gestione esplicita di blocco/uscita/revoca. Anche tutte le firme valide attestano materiale storico, non una nuova selezione TLS, consenso corrente o commit distribuito. La radice decodificata resta candidata, non indipendentemente fidata.

Dieci test comuni coprono binding/copie, ogni troncamento, limiti unsigned e massimi, input malformati/duplicati/UTF-8 e alterazioni legali non autorizzanti. Due regressioni P-256 verificano le firme rilette e rifiutano contesti alterati. Il test TLS esistente salva/rilegge il payload dal nuovo deposito SQLite e verifica pin/catena/entrambe le firme con certificati reali; SQLite riaperto ancora senza gruppo/trust/storia. Il deposito è descritto in [ADR 011](ADR-011-JOURNAL-ADOZIONE-LOCALE.md): non è commit di appartenenza o recovery di produzione. Evidenze correnti in STATO; nuovo Native/hardware non attestato.

## Attestazioni prima del journal recuperabile — 13 ottobre 2026

GroupAdmissionConfirmationReceipt conserva i byte difensivi del confronto e le due GroupAdmissionConfirmation direzionali, usando i codec esistenti. Il core trattiene la locale soltanto dal successo `sent` del ticket esatto, la remota soltanto dopo verifica e liveness; la snapshot interna richiede Confirmed vivo. Chiusura/revoca elimina le attestazioni dal tentativo. GroupRootAdoptionDraft le include nel rilascio monouso già esistente, senza nuova scrittura o autorizzazione.

Una ricevuta trattenuta non resta un permesso valido dopo revoca e non attesta commit distribuito, appartenenza o consenso nuovo dopo riavvio. La firma locale proviene dal signer OS fidato; il journal futuro deve conservare anche offerte/bootstrap/evidence/certificati e richiederà verifica completa, binding e recovery, non il solo booleano Confirmed. Nessuna nuova serializzazione journal o migrazione introdotta qui; nessun caller owner/servizio/UI nuovo. Test mirati JVM/Android, P-256 e TLS/SQLite riusciti; nuovo Native/Swift/hardware non attestato. Il checkpoint Apple precedente 485f008 ha eseguito 134 XCTest senza fallimenti, non questo incremento. Evidenze correnti in STATO.

## Owner Apple del destinatario candidato — 12 ottobre 2026

`GroupRootAdoptionChannel` possiede una NWConnection mutual-TLS pronta durante il confronto, usando IosGroupRootAdoption. Controlla identità del trasporto, certificato estratto da quella connessione e pin selezionato; il caller deve fornire offerte verificate sullo stesso canale dopo aver ritirato tutti gli I/O/timer dell'owner precedente. Nessun nuovo handover bootstrap/evidence è collegato al servizio. Policy DER/P-256 Apple, Keychain e firme esistenti riusate, certificati TLS reali prioritari; nessuna fiducia indipendente deriva dalla radice ricevuta.

Start verifica identità corrente e assenza di gruppo tramite IosPersistence prima del codice. Il confronto completo è SHA-256 dei byte Kotlin; solo il ticket preciso può richiedere la firma OS su coda separata. La write viene riconosciuta esclusivamente dal contentProcessed riuscito; anche dopo doppia conferma Confirmed resta revocabile e il DB del destinatario rimane senza appartenenza/trust. Timer originale attivo prima di start, chiusura socket su revoca/errore/EOF/scadenza, callback tardivi ignorati e primo motivo/cause originali mantenuti.

Tutte le operazioni/cambi identità/gruppo/lifecycle restano serializzati fuori dalla UI; preflight DB sincrono, non cancellazione non bloccante di SQLite fermo. Il chiamante mantiene vivo il driver fino al drain, l'owner non lo chiude. Nessun releaseForCommit, salvataggio remoto, autorizzazione applicativa o nuova UI. Sei XCTest aggiunti alla fixture TLS/Keychain esistente, con HELLO reali e riapertura SQLite; evidence/clic sono fixture. Compilazione/runtime del nuovo Swift ancora da attestare nel checkpoint completo. La facciata e i precedenti otto XCTest sono compilati dalla CI 76b85d4, non ancora eseguiti in simulatore. Stato corrente in STATO; collaudi fisici aperti.

## Confine Kotlin/Swift del destinatario candidato — 12 ottobre 2026

`IosGroupRootAdoption` espone il ciclo comune GroupRootAdoptionAttempt tramite snapshot finiti e ticket opachi, riusando framing/decoder. Solo il destinatario TLS delle offerte può costruirlo; identità corrente e radice locale assente sono controllate prima della prova. Un errore SQLite è rilanciato, non un gruppo vuoto. Buffer esposti sono difensivi, ticket firma/write sono legati all'istanza; la write deve essere riconosciuta soltanto dal futuro callback OS contentProcessed riuscito.

Non è ancora l'owner Network.framework: nessuna connessione, timer OS, policy certificati o firma è sostituita da questa facciata. Il futuro owner serializza tutte le chiamate/cambi identità/gruppo/lifecycle sulla stessa coda fuori dalla UI, lega offerte/verificatori agli endpoint TLS selezionati, schedula la scadenza originale anche mentre inattivo e chiude la connessione su CLOSED. Mantiene IosPersistence vivo fino al termine dei callback. Il preflight DB è sincrono, senza promessa di cancellazione non bloccante del driver.

Cancel/blocco/uscita/EOF/frame invalido/scadenza/duplicati revocano anche Confirmed e invalidano i callback tardivi. Nessun handoff al commit, salvataggio dell'appartenenza/trust o autorizzazione dei messaggi. Nessun caller servizio/UI. Verifica host sui sorgenti Kotlin effettivi con fixture del confine IosPersistence e JDBC/riapertura reali; crypto/clock sono test double, non nuove prove TLS o Apple. Otto XCTest predisposti; Native/export/Swift/runtime ancora da attestare. Prossimo blocco: owner Swift isolato con API/identità Apple già esistenti, prima del commit remoto recuperabile.

## Owner del confronto candidato JVM/Android — 12 ottobre 2026

`GroupRootAdoptionConnection` possiede un singolo socket TLS 1.3 selezionato/autenticato reciprocamente durante il confronto del nuovo membro. Firma con Identity OS, verifica con la policy dei certificati e usa framing/decoder e GroupRootAdoptionAttempt comuni. Il pin/certificato del canale prevale sull'evidence; quella ricevuta non stabilisce automaticamente una radice fidata.

Il chiamante deve fornire offerte verificate su quel socket, ritirare il precedente owner e mantenere DB/scheduler vivi fino a close e join degli I/O. La firma e le write non tengono il lock di lifecycle; timeout inattivo, cancel, blocco, uscita e perdita del canale abortiscono il socket. Rifiuti false/null aggiornano subito lo stato terminale. Una write completata dopo revoca non promuove il tentativo. Il preflight DB è sincrono serializzato: non si promette cancellazione non bloccante di un driver fermo. Il futuro servizio serializza anche cambi di identità/gruppo e invalida il tentativo.

L'owner non espone handoff al commit: Confirmed è ancora revocabile, non appartenenza durevole o autorizzazione applicativa. Nessuna chiamata Node/UI, adozione persistente, nuovo handover bootstrap o owner Apple in questo incremento. Test TLS reali verificano consenso/revoca/timeout/framing e riapertura SQLite ancora vuota; non sono collaudi fisici. Il checkpoint 834648e ha ora verificato il core precedente anche Native (296 protocollo, otto SQLite e 120 XCTest), non questo adattatore JVM. Evidenze correnti in STATO; sezioni sotto storiche.

## Radice candidata e consenso della connessione — 12 ottobre 2026

`GroupRootAdoptionAttempt` è il ciclo comune del nuovo destinatario prima della persistenza. Diversamente da un membro con radice durevole indipendente, parte da **proof.anchor non attendibile**. La verifica completa della catena stabilisce solo coerenza/firme rispetto a quella candidata, non fiducia esterna: non si presenta VerifiedChain come appartenenza. Un peer LAN non può fare adottare una radice con il solo payload, HELLO o READY.

Il confronto usa gli stessi byte canonici GroupAdmissionConfirmationContext, inclusi radice, percorso, firme, ruoli, nonce e capability delle offerte TLS selezionate. GroupAdmissionConfirmationAttempt resta proprietario del ticket opaco; solo il clic esplicito su quel confronto completo può richiedere la firma direzionale locale. Firma remota verificata e write locale effettivamente riuscita sono entrambe obbligatorie. Non si aggiunge una conferma abbreviata, firma o formato wire diverso.

Il wrapper controlla identità locale destinataria e radice assente prima di verificare la prova e nuovamente prima del rilascio. Un gruppo esistente, anche identico, è rifiutato senza sostituirlo. Errore di lettura non è null; non vi sono retry/scritture. Read reentrante non può produrre due bozze o riavviare preparazione; cancel/blocco/uscita/EOF/scadenza e callback tardive invalidano anche Confirmed. Il watermark delle offerte alimenta il ciclo comune senza cambiare l'istante della selezione: non ripartono i 120 secondi, clock arretrato/overflow sono rifiutati.

`GroupRootAdoptionDraft` conserva proof/membro/byte difensivi del confronto; ReleasedForCommit è un handoff monouso, **non adozione durevole o autorizzazione**. Il futuro owner trasferisce separatamente socket/timer/deadline e gestisce cancellazione dopo handoff, ricontrollando identità, blocchi e assenza di appartenenza nella transazione di commit recuperabile. Uno snapshot vuoto non prenota SQLite e non protegge cambi esterni A→B→A. LocalGroupRepository/foundLocalGroup restano il contratto della sola fondazione; non si usa quell'INSERT per adottare radici remote. Credenziali persistenti, commit distribuito, owner OS e integrazione UI/servizio restano aperti.

20 regressioni comuni, quattro P-256 reali e una nuova integrazione pinned TLS 1.3/DER/SQLite verificano candidato → confronto completo → doppia conferma → handoff, senza gruppo/trust nemmeno alla riapertura del DB. Clic e orchestrazione sono fixture test, non un nuovo servizio. Nuovo ciclo non ancora Native/Apple attestato; il checkpoint precedente b38b4c0 ha invece verificato la prova del fondatore: 276 protocollo Native, sei SQLite e 120 XCTest riusciti. Evidenze/comandi correnti in STATO; collaudi fisici aperti.

## Preparazione della prima prova dal fondatore — 12 ottobre 2026

`FounderGroupAdmissionDraft` prepara una singola delega dal fondatore corrente a un altro dispositivo, riutilizzando claim/byte/firma/proof v1 esistenti. `prepareSigned` legge la radice tramite LocalGroupRepository, valida fondatore e destinatario prima degli adattatori OS, firma/verifica copie indipendenti dei byte canonici e rilegge la radice prima di restituire. Nessuna generazione di gruppo, self-admission, normalizzazione, retry o scrittura. Un errore OS/lettura/verifica rifiuta la prova e propaga il guasto; l'ultimo snapshot non promette atomicità fra OS/database o contro modifiche esterne A→B→A.

L'adattatore JVM/Android usa Identity e GroupAdmissionCertificateVerifier esistenti. La facciata IosFounderGroupAdmission confeziona anche il certificato pubblico con il codec comune; Swift fornisce il DER della propria AppleIdentity, firma e verifica tramite policy OS. Callback nullable segnala fallimento di firma senza fallback; Swift conserva l'errore OS originale. La facciata controlla la sintassi DER/Base64, non certificati arbitrari: pin/DER/chiave sono responsabilità OS e del verificatore evidence ricevente. Nessuna nuova primitiva, versione, credenziale o libreria.

Il risultato è **evidence non autorizzante**, non consenso utente, appartenenza, adozione remota o commit. Il percorso è riservato al fondatore: un membro delegato richiederà la propria catena durevole verificata, mai l'identità del fondatore presa da un payload. Il futuro owner serializza richieste, identità, gruppo/uscita e durata DB fuori dalla UI; se il tentativo scade/viene cancellato prima dell'invio deve scartare la prova. Non vi sono caller nel servizio/UI. Le conferme restano quelle del contesto live separato, non questa firma lunga durata.

14 regressioni comuni e sette OS/SQLite; un nuovo percorso con fondazione riaperta → firma reale → bootstrap/TLS/doppia conferma dimostra che persino Confirmed non scrive appartenenza/trust. La radice attesa e i clic sono fixture esplicite di test, non implementano l'adozione remota. Dieci smoke host della facciata riusciti; tre XCTest Apple predisposti, verifica Native/export/Swift/runtime del nuovo codice ancora necessaria. Stato corrente/evidenze finali in STATO, niente hardware nuovo. Le sezioni successive sono storiche.

## Preparazione locale della fondazione — 11 ottobre 2026

**Ultimo blocco Apple, ancora locale:** commit delegato a `GroupFoundationAttempt` comune su entrambi gli owner, facciata `IosLocalGroupFoundation` e adattatore Swift con AppleIdentity/SecRandomCopyBytes esistenti. Radice rileggibile da IosPersistence, ticket opachi, nessuna scrittura arbitraria esposta a Swift. Errori OS/DB osservabili, niente fallback/replay dopo handoff; cancellazione e `leaveGroup` riguardano la sola richiesta, non eliminano il gruppo persistito. Suite finali: **286 protocollo JVM / 257 unit Android / 10 SQLite / 133 connettività JVM**, zero errori/fallimenti, un multicast opt-in skipped; metadata comuni e Android compilati. Dieci scenari host della facciata Kotlin su JDBC con fixture del confine IosPersistence, non Native/Swift. Quattro nuovi test Native e undici XCTest predisposti, non compilati/eseguiti. Nessun servizio/UI attivato, push o CI. I conteggi seguenti sono storici.

**Aggiornamento locale persistente:** [ADR 010](ADR-010-FONDAZIONE-LOCALE-PERSISTENTE.md), `LocalGroupRepository`, schema 2 con migrazione additiva e singleton. INSERT condizionale atomico, mai overwrite; nome/trust/messaggi esistenti conservati. `LocalGroupFoundation.commit()` JVM/Android salva prima di Committed e non ripete ticket ceduti dopo errore. Identità OS e cancellazione serializzate dal futuro servizio; assenza di gruppo arbitrata dentro la transazione, nessuna promessa di transazione distribuita OS/DB. Otto test SQLite e 133 connettività JVM riusciti (un multicast opt-in skipped), APK debug e desktop compilati. Tre nuovi test iOS predisposti ma non compilati/eseguiti. Nessuna chiamata attiva, peer autorizzato o adozione remota: i paragrafi storici che indicano schema/commit non implementati descrivono i blocchi precedenti, non questo codice locale. Uscita durevole e ammissione distribuita restano aperte. Nessun push/CI.

**Owner OS aggiunto localmente, senza push:** `LocalGroupFoundation` JVM/Android collega il tentativo condiviso alla stessa `Identity` e a SecureRandom esistenti; nessun generatore arbitrario fornito dal servizio. Chiamate serializzate dal futuro servizio, fuori dal thread UI. Rilascio ricontrolla l'identità corrente e non sostituisce i controlli della futura transazione SQLite. Nessun chiamante attivo, persistenza o trust. Il ciclo comune distingue CancellationException da guasto OS, rilanciando la stessa eccezione e conservando eventuale primo motivo di chiusura. Due nuove regressioni comuni e cinque integrazioni OS: **22 JVM / 22 unit Android / sette integrazioni JVM** riuscite, compilazione Android riuscita. Non Native/Swift/hardware; schema/wire/versioni/lock invariati.

**Ciclo locale successivo, non ancora consegnato:** `GroupFoundationAttempt` possiede una sola preparazione e un ticket opaco monouso. Cancel/uscita prima del rilascio invalidano la bozza; callback OS reentrante non ripristina il tentativo, guasti vengono rilanciati conservando il primo motivo di chiusura. Prima di `releaseForCommit` vengono ricontrollati identità e assenza di appartenenza; ticket estranei, duplicati e preparazioni reentranti non avanzano. Il rilascio è terminale e trasferisce responsabilità al futuro owner del commit: **non significa persistenza riuscita**. Dopo il rilascio il vecchio owner non può annullare il ricevente; quest'ultimo deve gestire cancellazione e ricontrolli nella transazione. Snapshot null e ticket non prenotano righe SQLite. Nessun chiamante attivo o schema modificato. Tredici nuove regressioni comuni più sette draft: 20 JVM / 20 unit Android riusciti, non Native/Apple/hardware.

`GroupFoundationDraft.prepare` prepara una radice locale distinta dall'auto-ammissione: identità esistente con pin canonico e un solo ID gruppo da 256 bit generato dall'adattatore OS. Rifiuta un'appartenenza corrente prima di invocare la casualità, controlla la rappresentazione senza normalizzare e propaga gli errori senza retry/fallback. La validazione non dimostra entropia; il callback è una dipendenza OS fidata, non input di rete. `prepareLocalGroupFoundation` JVM/Android riusa `Identity` e `randomNonce`/SecureRandom esistenti, senza ruotare chiavi o derivare ID da LAN/sessione.

È soltanto una **bozza non persistita**, non fondazione completata, prova firmata, autorizzazione o prenotazione atomica. Il futuro owner deve serializzare richiesta esplicita, preparazione e commit con cambi di appartenenza/uscita, ricontrollare identità e assenza di gruppo e persistere prima di pubblicare. Non riusare la bozza dopo cancellazione; due preparazioni su snapshot null non impediscono da sole due commit concorrenti. Nessun chiamante nel servizio/UI, schema o wire modificato; adozione della radice remota e commit recuperabile restano aperti. Non introdotto un nuovo formato di firma o auto-ammissione del fondatore.

Verifiche: sette casi comuni eseguiti su JVM/unit Android, nove regressioni di catena per target, due integrazioni JVM con identità/firme/casualità OS reali; compilazione adattatore Android riuscita. Nuovo codice non ancora verificato Native/Apple/hardware. Il checkpoint precedente `4776fb0`, [38158675197](https://github.com/zanzaro-mirco/lantern-share/actions/runs/38158675197), ha eseguito Native e **101 XCTest senza fallimenti**, inclusi i 44 casi owner/framing/vettori; non copre questa nuova preparazione.

Le sezioni successive conservano il contratto e le evidenze storiche; la preparazione qui descritta non completa i percorsi di fondazione/adozione ancora indicati come aperti.

Incremento di dominio preparatorio al protocollo v1: `GroupAdmissionClaim` contiene gruppo, emittente e destinatario. È una **dichiarazione non firmata**, non una credenziale verificata o un'appartenenza autorizzata. Non sostituisce l'ammissione PoC wire 0 né `ProtocolHandshakeApproval`, che prova solo il transcript della connessione corrente.

Gli ID nel dominio sono opachi e non vuoti; non vengono normalizzati. Emittente e destinatario devono essere diversi. L'auto-ammissione è rifiutata: la fondazione del gruppo richiederà un percorso distinto. Non sono introdotti ruoli amministrativi, scadenze o revoche globali assenti dalla specifica.

`bindingTo(groupId, issuerId, memberId)` confronta esattamente tutti i campi con un contesto stabilito indipendentemente dalla dichiarazione. Distingue gruppo, emittente o destinatario discordante; `MATCHED` significa soltanto corrispondenza strutturale. **Non significa firma valida, emittente autorizzato, conferma utente o protezione dai replay.** Passare come contesto gli stessi campi appena ricevuti non verifica nulla.

L'appartenenza futura sarà legata al gruppo, non a SSID, IP o sessione LAN, così da persistere al cambio rete. Prima di accettare e persistere una credenziale serviranno almeno:

- formato canonico versionato con dominio di firma distinto, validazione degli ID crittografici e limiti del payload;
- firma verificata con l'identità dell'emittente e prova della sua appartenenza al medesimo gruppo;
- collegamento al processo di ammissione e alle conferme esplicite previste, senza promozione da mDNS o dal solo `READY`;
- gestione dell'emittente iniziale, delle ammissioni delegate e del completamento recuperabile, prima di integrare trust e database.

Il formato, il controllo di firma, la verifica isolata di una catena ancorata e il contenitore della prova completa descritti sotto sono implementati. Restano da implementare la fondazione/adozione confermata della radice, lo scambio nel servizio attivo, il processo di ammissione recuperabile e l'integrazione trust/database. Il confronto non include un contatore d'ammissione alla sessione: esclusione della cronologia anteriore e destinatari dei messaggi restano regole separate da implementare.

Verifica: nove casi comuni per corrispondenza, sostituzioni dei tre campi, inversione dei ruoli, auto-ammissione, campi/contesto vuoti e confronto senza normalizzazione. Eseguiti con `./gradlew -Pandroid=true :domain:jvmTest :domain:testDebugUnitTest --console=plain`; includendo le otto regressioni sessione, 17 test per target. Test unitari Android su JVM, non hardware; Native richiede checkpoint manuale. Nessuna migrazione SQLite, modifica wire, versione o lock.

## Formato isolato v1

`GroupAdmissionCodec` codifica quattro campi obbligatori, nell'ordine canonico `version`, `group`, `issuer`, `member`. Versione esattamente il numero JSON `1`: stringhe, spellings numerici alternativi e versioni sconosciute sono rifiutati. Nessun fallback al wire 0.

Tutti e tre gli ID sono esattamente 64 caratteri esadecimali minuscoli. Il gruppo rappresenta un valore casuale da 256 bit, indipendente da rete e dispositivo; le identità mantengono il pin SHA-256 del DER del certificato. Si riusa la validazione sintattica esistente, non la semantica del certificato per il gruppo. Generazione casuale e verifica certificati non sono eseguite dal codec. Il modello di dominio rimane opaco; è il confine protocollo a imporre queste rappresentazioni.

Payload unsigned: massimo 512 byte UTF-8, profondità JSON massima 1. Payload `SignedGroupAdmissionCodec`: massimo 1024 byte, profondità 2, due campi obbligatori `claim` e `signature`:

```json
{"claim":{"version":1,"group":"<64 hex>","issuer":"<64 hex>","member":"<64 hex>"},"signature":"<Base64 canonico>"}
```

L'esempio usa segnaposto, non è un payload valido. La versione appartiene alla dichiarazione annidata: un secondo campo `version` esterno è sconosciuto e rifiutato. Il serializer annidato è lo stesso di quello unsigned, non una seconda implementazione della validazione. Il limite del documento annidato è quello dell'envelope completo; il limite standalone di 512 byte non è un secondo limite sul whitespace interno all'envelope.

Ordine/whitespace/escape JSON validi non cambiano la dichiarazione né i byte da firmare. Duplicati, anche con nomi escaped equivalenti, campi mancanti/sconosciuti, tipi errati e auto-ammissione sono rifiutati. Dimensione, UTF-8 rigoroso e profondità sono controllati prima della deserializzazione. Il test di profondità è deliberatamente **entro il limite di byte**, per non confonderlo con il rifiuto oversize; UTF-8 invalido richiede `CharacterCodingException`, secondo la [API Kotlin](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.text/decode-to-string.html), non un generico errore di runtime.

La firma usa Base64 standard canonico, 4–256 caratteri, con padding/bit inutilizzati corretti. La regola sintattica è condivisa con APPROVE, la cui API/semantica rimane invariata. La sintassi accetta anche byte che non sono una firma DER/ECDSA valida: `SignedGroupAdmission` è un contenitore **non verificato**, non un'autorizzazione.

## Byte canonici e vettore

`GroupAdmissionCodec.signedBytes` concatena campi con prefisso `lunghezzaDecimaleUTF8:valore`, senza separatori aggiuntivi, in quest'ordine:

1. `lantern-group-admission-1`;
2. `1`;
3. gruppo;
4. emittente;
5. destinatario.

Il dominio distinto impedisce confusione con transcript, APPROVE o firma wire 0. I ruoli non vengono ordinati: invertirli cambia i byte. Si firmano questi byte ricostruiti, **non il JSON ricevuto**. Le firme ECDSA SHA-256 DER rimangono compito delle API OS, non di un algoritmo Kotlin nuovo.

Vettore pubblico indipendente (.NET SHA-256 e JCA): gruppo `c` × 64, emittente `a` × 64, destinatario `b` × 64. JSON canonico unsigned: 240 byte. Byte da firmare: 232 byte, prefisso `25:lantern-group-admission-11:1`, seguito dai tre campi `64:<ID>`. SHA-256: `3e3fcddb32360c5166a63cdfc093b17ab6043a7acf51755bae7e7ce40cb43029`.

Le prove P-256 JVM reali verificano round-trip dell'envelope e rifiuto con chiave, gruppo, emittente, destinatario, direzione, versione o dominio cambiati. Non provano che gli ID fixture corrispondano a certificati reali, né interoperabilità Apple del nuovo formato.

## Controllo di firma, non appartenenza

`GroupAdmissionSignatureVerification.verify` riceve contesto atteso, fingerprint del certificato del firmatario e callback OS legata **alla chiave di quello stesso certificato**. Il contesto e il pin devono essere stabiliti indipendentemente dal payload; copiare i campi ricevuti nei parametri non è una verifica d'identità o di gruppo.

Prima di chiamare il verificatore controlla gruppo/emittente/destinatario e pin dell'emittente; poi passa i byte canonici e la firma. Firma invalida → `InvalidSignature`; errori inattesi dell'adattatore propagati, mai trasformati in successo. L'adattatore deve restituire false per DER/firme invalide riconosciute dal verificatore OS. I test comuni usano un sostituto solo per provare ordine/binding/errori; quelli JVM usano firme P-256 reali.

`VerifiedSignature` significa esclusivamente corrispondenza e firma verificata sul certificato dichiarato dal contratto dell'adattatore. **Non prova che l'emittente sia membro autorizzato**, non fonda il gruppo, non attesta conferme, non rende recuperabile il commit, non autorizza messaggi e non scrive trust. Una credenziale persistente può legittimamente essere ripresentata al cambio rete; la firma da sola non è protezione anti-replay del processo interattivo.

Prima dell'attivazione servirà una radice di gruppo verificabile e una catena di ammissioni delegate senza autorizzazioni circolari, oltre a conferme esplicite, completamento recuperabile e rispetto dei blocchi locali. Nessun certificato sconosciuto va accettato automaticamente in base al solo envelope o a `VerifiedSignature`.

Il verificatore è sincrono e senza stato: non possiede socket, timer o tentativi e non rende immutabile l'autorizzazione del contesto. Il futuro proprietario deve mantenere il legame tra risultato, dichiarazione e tentativo corrente, e ricontrollare appartenenza/blocco/uscita dal gruppo prima del commit. Un risultato conservato non deve ripristinare una selezione cancellata o autorizzare un'altra dichiarazione. La gestione di questa concorrenza non è implementata dal codec.

## Verifica attuale

Nuovi test: 11 codec unsigned, 7 envelope, 5 verificatore comune, 3 JVM con SHA-256/P-256 reali. Suite protocollo con regressioni esistenti: **126 JVM, 119 unit Android**, zero errori/fallimenti/skipped. Native e integrazione Apple del nuovo codice non ancora eseguiti; test comuni inclusi nel checkpoint iOS manuale già esistente. Formato completamente isolato dal servizio PoC, schema SQLite e identità invariati.

## Radice e ammissioni delegate — incremento successivo

`GroupTrustAnchor(groupId, founderId)` identifica l'origine del gruppo stabilita **indipendentemente dalla prova ricevuta**. Il costruttore valida soltanto ID opachi non vuoti: non fonda il gruppo, non verifica un certificato e non autorizza l'adozione della radice annunciata da un peer. Al confine protocollo gruppo/fondatore/destinatario atteso devono essere 64 hex minuscoli. La futura fondazione locale richiederà generazione OS casuale e identità persistente; l'adozione da parte di un nuovo membro richiederà binding alle conferme del bootstrap. Entrambi i percorsi restano non implementati.

`GroupAdmissionChainVerification.verify` riceve questa radice, il destinatario atteso e **un percorso ordinato** di `SignedGroupAdmission`: fondatore → membro → eventuali altri membri → destinatario. Non cerca un percorso in un grafo ostile. Ogni dichiarazione deve appartenere allo stesso gruppo, avere come emittente il destinatario precedente e introdurre un'identità non ancora visitata. Una lista vuota non prova la fondazione; auto-ammissioni, ritorni al fondatore, cicli, frammenti scollegati, riordino e destinatario finale diverso sono rifiutati. Si controlla tutta la struttura prima di invocare la crittografia; non si espongono appartenenze parziali.

La funzione conserva una copia della lista limitata prima dei callback (le dichiarazioni sono immutabili). L'input deve essere uno snapshot posseduto dal chiamante, non una collezione modificata concorrentemente durante la copia. Ogni firma è verificata sui byte canonici già definiti. Il callback OS riceve il fingerprint **atteso** dell'emittente: deve risolvere/verificare il certificato con quel fingerprint e usare la chiave dello stesso certificato. Chiave sconosciuta, pin discordante o firma invalida → false; errori inattesi e cancellazione propagati. Questo adattatore certificati non è ancora integrato: i test comuni sostituiscono solo il callback e quelli JVM usano chiavi P-256 effimere con ID fixture dichiarati, non certificati/Keychain.

`VerifiedChain` prova esclusivamente le firme e il percorso fino alla radice fornita. Non è un token di autorizzazione, non conferma il tentativo corrente, non risolve replay/commit o blocchi locali e non scrive nel trust. Non basta passare la radice ricevuta per rendere affidabile una catena. Prima del commit il futuro proprietario dovrà ricontrollare radice corrente, dichiarazione/destinatario, conferme, blocco/uscita e cancellazione del tentativo. Nessuna promozione da `READY`.

Limite isolato: **32 dichiarazioni per percorso**, controllato prima della copia o delle firme per limitare memoria/lavoro crittografico. Non limita a 32 i membri del gruppo e non cambia il wire esistente; un percorso più lungo viene rifiutato esplicitamente, mai troncato. Il formato della prova completa è definito sotto; la gestione di percorsi troppo lunghi resta da definire prima dell'attivazione. Il fondatore è una radice storica, non un amministratore o un server: non deve essere online per verificare una prova e ogni membro verificato può delegare. Nessuna revoca globale aggiunta.

Verifica locale del nuovo incremento: tre test dominio, nove comuni di catena e due JVM P-256 reali (round-trip codec, chiave sbagliata/mancante per ciascun emittente, cambio gruppo/destinatario). Suite complessive **20 dominio per target, 137 protocollo JVM/128 unit Android**, zero errori/fallimenti/skipped. Android unit su JVM; nessun collaudo fisico o esecuzione Native della nuova catena. API completamente isolate da rete/UI/SQLite, nessuna migrazione o nuova dipendenza.

## Prova completa v1 — 8 ottobre 2026

`GroupAdmissionProofCodec` definisce l'envelope isolato, con campi obbligatori nell'ordine canonico `version`, `anchor`, `admissions`:

```json
{"version":1,"anchor":{"group":"<64 hex>","founder":"<64 hex>"},"admissions":[{"claim":{"version":1,"group":"<64 hex>","issuer":"<64 hex>","member":"<64 hex>"},"signature":"<Base64 canonico>"}]}
```

Segnaposto illustrativi, non un payload valido. La versione esterna deve essere esattamente il numero JSON `1`; ogni dichiarazione conserva la propria versione firmata, senza fallback al wire 0. La radice contiene soltanto gruppo e fondatore, entrambi 64 hex minuscoli. Nessun ruolo amministrativo, certificato o chiave privata nel contenitore; il resolver dei certificati resta responsabilità dell'adattatore OS non ancora integrato.

Limiti: **32768 byte UTF-8 totali**, profondità massima **4** (envelope → array → ammissione → dichiarazione), **1–32 ammissioni**. L'elemento 33 è rifiutato prima di deserializzarne il contenuto. Il limite totale governa anche il whitespace delle dichiarazioni annidate: i limiti standalone 512/1024 byte dei codec singoli non sono ulteriori limiti per elemento. ID e firme mantengono tutti i vincoli esistenti tramite gli stessi serializer. Campi sconosciuti, mancanti, duplicati anche escaped, tipi/versioni sbagliati, UTF-8 invalido e profondità eccessiva sono rifiutati. Nessun troncamento o salto di elementi malformati.

`GroupAdmissionProof` è un contenitore **non verificato**: copia il percorso all'ingresso e restituisce copie nelle letture; il chiamante non deve modificare concorrentemente l'input durante la copia. Il codec non controlla topologia/firme, non conserva trust e non adotta la radice. Si usa l'overload `GroupAdmissionChainVerification.verify(proof, expectedAnchor, expectedMemberId, callback)` con radice/destinatario stabiliti indipendentemente: `AnchorMismatch` rifiuta entrambe le possibili sostituzioni della radice prima della crittografia; poi valgono tutti i controlli di catena precedenti. Passare `proof.anchor` come radice attesa annulla questo confine di sicurezza.

Nessuna firma aggiuntiva sull'envelope: le ammissioni firmano già versione/gruppo/emittente/destinatario; la radice deve coincidere con quella locale e ordine/continuità/destinatario sono verificati. Il contenitore non è una dichiarazione di fondazione. Una prova vuota non può autorizzare il fondatore. Prima della fondazione/adozione di una nuova radice servirà il collegamento esplicito alle conferme del bootstrap; non si può inferirlo dalla ricezione di un JSON valido o dal solo `VerifiedChain`.

Nuove verifiche: 11 test comuni del formato/prova e una integrazione JVM P-256 del round-trip completo, firma di entrambi gli emittenti e radice alternativa. Il caso da 32 elementi controlla il limite sintattico, non dichiara verificata una catena con identità ripetute. Nessuna integrazione nel wire attivo, SQLite o UI; nessun test fisico/Native del nuovo formato.

## Binding crittografico delle conferme — 8 ottobre 2026

Le firme `ProtocolHandshakeApproval` esistenti coprono il transcript bootstrap, **non la prova di gruppo**. Il loro `READY` non consente quindi l'adozione della radice né l'ammissione. Non si modifica APPROVE per assegnargli implicitamente un significato diverso.

`GroupAdmissionConfirmationContext` congela i byte di un contesto separato. Riceve le offerte bootstrap compatibili, con identità TLS verificate e nonce OS freschi, la radice attesa indipendente e la prova. Richiede radice corrispondente e ruoli uguali all'ultima ammissione: emittente attuale → nuovo membro. Il costruttore **non verifica la catena o le firme**; un contesto costruito non è una credenziale. La verifica dell'intera catena resta obbligatoria prima di proseguire, senza adottare automaticamente la radice proposta dal peer.

Byte di confronto canonici: prefissi `lunghezzaDecimaleUTF8:valore`, concatenati in ordine:

1. `lantern-group-admission-confirm-1`;
2. identità dell'emittente;
3. identità del nuovo membro;
4. transcript bootstrap completo, prodotto da `ProtocolHandshakeTranscript.bytes`;
5. JSON canonico della prova completa, prodotto da `GroupAdmissionProofCodec.encode`.

Le viste `comparisonBytes()` sono copie difensive. Il futuro adattatore calcolerà SHA-256 OS per mostrare il codice completo su entrambi i dispositivi. Ordine/whitespace/escape del JSON ricevuto non lo cambiano; firma, radice, ordine del percorso, nonce o capability diversi invece lo cambiano. Due firme ECDSA diverse sulla stessa dichiarazione producono intenzionalmente due contesti diversi: entrambi devono confrontare **la stessa prova completa**, non soltanto una dichiarazione equivalente.

`approvalBytes(senderIdentity)` aggiunge un dominio e una direzione distinti, ancora con lunghezze UTF-8: `lantern-group-admission-confirm-approve-1`, mittente, destinatario, byte di confronto completi. Sono i byte per la futura firma OS dopo conferma esplicita di questo confronto. Non sono il JSON o la firma della credenziale persistente e non possono sostituire APPROVE bootstrap o wire 0. Nessun nuovo frame di rete viene attivato in questo incremento.

`GroupAdmissionConfirmationVerification.verifyRemote` controlla ruoli/destinatario e fingerprint del peer TLS prima del callback OS sullo stesso certificato; controlla Base64 canonico e verifica la firma direzionale. Firma invalida → rifiuto; errori inattesi/cancellazione propagati. `VerifiedRemoteConfirmation` significa **una sola attestazione crittografica remota**, non due conferme, catena valida, tentativo corrente o trust persistente. Non dimostra che l'utente remoto abbia premuto un pulsante: l'emissione della firma deve essere governata dal proprietario remoto e dalla sua conferma esplicita.

Limite dei componenti stateless: non possiedono ticket, connessione, timer o transazione e non invalidano da soli un risultato vecchio. Il ciclo di vita condiviso descritto sotto ora governa ticket/conferme/esito write e invalidazione, ma gli adattatori di rete/timer/UI devono ancora esservi collegati. Fondazione/adozione della radice, resolver certificati e commit recuperabile restano non implementati. Nessuna integrazione nel servizio/UI/database.

Verifica locale: sette nuovi casi comuni di binding/ordine/errori e due JVM P-256 reali. **158 protocollo JVM/146 unit Android**, zero errori/fallimenti/skipped; metadata comuni e compilazione Android/desktop riusciti. Coperti entrambe le direzioni, chiave errata, firme bootstrap/ammissione non riutilizzabili, nonce/gruppo/fondatore/firma della prova sostituiti, capability, normalizzazione JSON, buffer, ruoli/ancora incompatibili e cancellazione propagata dal verificatore. Non sono test di cancellazione di un proprietario, TLS/certificati reali, Native o hardware. Nessuna versione/lock/migrazione modificata.

## Tentativo di conferma gruppo — ciclo di vita condiviso

`GroupAdmissionConfirmationAttempt` possiede un solo contesto immutabile e i suoi ticket. Non gestisce socket, repository o primitive OS. Il proprietario della connessione deve serializzare **tutte** le chiamate sulla stessa coda, fornire identità/offerte TLS e pin scelti per quel canale, usare nonces freschi a ogni riconnessione e inoltrare tempestivamente blocco, uscita, cancellazione ed EOF. Non si può riutilizzare o resettare un tentativo chiuso.

`prepare()` verifica l'intera prova tramite il callback OS, che deve risolvere ciascun certificato rispetto al pin atteso, e soltanto dopo restituisce il ticket di confronto. Prova malformata/firma invalida non espongono il confronto; radice/ruoli restano quelli congelati nel contesto indipendente. Il componente non adotta una nuova radice. Prima della fondazione/adozione confermata resta necessario il percorso di prodotto separato.

La UI mantiene l'oggetto `GroupAdmissionComparison` esatto; `confirm(ticket)` dopo il confronto esplicito del codice completo produce un ticket `Sign` con copia dei byte da firmare. Il callback OS `signed(request, signature)` deve firmare esattamente quei byte con la chiave dell'identità TLS locale; produce dati `Send` separati da APPROVE bootstrap, non ancora un frame di rete. Solo `sent(send)` nel callback di **scrittura realmente completata**, non dopo l'accodamento, attesta la progressione locale. Ticket di altri tentativi, riutilizzati o revocati non avanzano lo stato; le viste di byte sono copie.

La conferma remota può arrivare prima/durante/dopo firma e scrittura locali, ma solo dopo la prova verificata. Deve avere direzione corretta e firma OS del peer TLS sullo stesso contesto. `Confirmed` richiede **catena verificata, conferma esplicita locale, scrittura locale riuscita e firma remota verificata**. Duplicati, riflessioni, ingresso prima della prova o rientranza del verificatore remoto chiudono il tentativo. Nessuna appartenenza parziale è esposta.

Scadenza: 120000 ms dalla selezione originale, sullo stesso orologio monotono del bootstrap; `prepare()` non riavvia il budget. `state` e `remainingMillis` applicano la scadenza anche a `Confirmed`; arretramento/overflow o guasto dell'orologio non lasciano uno stato attivo. Il proprietario deve comunque programmare un timer usando il budget residuo per chiudere il trasporto anche quando nessuno chiama il core.

`cancel()`, `block()`, `leaveGroup()` e `transportClosed()` chiudono anche `Confirmed`, conservano il primo motivo e invalidano ticket. Il core ricontrolla stato/deadline dopo i callback di verifica; un callback che cancella/blocca il tentativo o termina dopo la scadenza non ripristina il progresso. Errori inattesi/cancellazione chiudono e vengono rilanciati. La conferma non costituisce una transazione: il futuro proprietario dovrà verificare ancora tentativo/radice/blocco/uscita correnti prima del commit e implementare il completamento distribuito recuperabile. Nessun messaggio o trust persistente viene autorizzato qui.

Verificato locale: 13 nuovi test comuni di ciclo di vita e un JVM con due tentativi/P-256 reale, chiavi effimere e ID fixture (non TLS o certificati reali). Suite protocollo **172 JVM/159 unit Android**, zero fallimenti/errori/skipped. Prova obbligatoria/rotta, entrambe le sequenze e quattro tempi della conferma remota, ticket stranieri, write/sign falliti, pin sostituiti, chiusure anche dopo conferma, cancellazione/blocco/timeout nei callback, rientranza, guasto/arretramento/overflow dell'orologio. Metadata comuni e Android/desktop compilati; unit Android su JVM, non hardware/Native. Wire 0/SQLite/versioni/lock invariati. Adattatori timer/UI/rete e resolver certificati ancora non integrati.

## Messaggio e framing delle conferme gruppo

`GroupAdmissionConfirmationCodec` codifica un messaggio dedicato con cinque campi obbligatori, nell'ordine canonico:

```json
{"version":1,"type":"GROUP_CONFIRM","sender":"<64 hex>","recipient":"<64 hex>","signature":"<Base64 canonico>"}
```

Segnaposto illustrativi. Versione esattamente numero JSON `1`, tipo esattamente stringa `GROUP_CONFIRM`; identità distinte/64 hex minuscoli e stessa regola Base64 delle altre firme. Nessun campo facoltativo o fallback: campi mancanti/sconosciuti/duplicati escaped, versioni numeriche alternative, tipi errati, UTF-8 invalido e nesting sono rifiutati. Limite payload **1024 byte**, profondità **1**. JSON valido è soltanto un'attestazione ricevuta non verificata, non una conferma utente/trust.

La firma resta sui byte di `GroupAdmissionConfirmationContext.approvalBytes`, non su questo JSON. Il messaggio non include una copia della radice/prova o un digest dichiarato dal peer: è il contesto corrente posseduto dall'adattatore a determinare i byte della verifica. Replay su contesto/nonce diverso deve fallire; ticket e stato del tentativo rimangono obbligatori. Tipo dedicato impedisce il routing come APPROVE bootstrap; né il decoder bootstrap né il wire 0 accettano questo messaggio, e il decoder gruppo rifiuta i loro messaggi.

`GroupAdmissionConfirmationFraming`: header di **4 byte uint32 big endian**, lunghezza **1–1024**, verificata prima dell'allocazione. Solo la primitiva interna `BoundedFrameLength` è condivisa col framing bootstrap; limiti, API/diagnostica bootstrap e formato precedente preservati. Decoder specifico `GroupAdmissionConfirmationFrameDecoder`: massimo chunk **1028 byte**, massimo payload incompleto 1024, frammenti/copertura multipli elaborati sulla coda seriale del proprietario. Buffer d'ingresso copiati, ordine conservato e nessun reset/riuso.

EOF su header/payload incompleto fallisce; EOF pulito, errore o cancellazione chiudono definitivamente il decoder. Un tail malformato nello stesso chunk non restituisce un batch parziale. Errori di JSON/UTF-8 vengono esposti come `Invalid group confirmation frame` senza causa o contenuto peer. I frame già consegnati in un chunk precedente non possono essere ritirati dal parser: il proprietario dovrà invalidare il tentativo e chiudere il trasporto anche dopo una conferma. `close()` è idempotente e scarta il payload incompleto; non chiude il socket OS.

Encoder per `Send` del tentativo disponibile, ma codificare o accodare **non** chiama `sent` né attesta una scrittura. Il bridge callback descritto sotto ora collega decoder/ticket/tentativo/EOF; gli adattatori OS devono ancora esservi collegati. Nessun nuovo chiamante nel servizio/UI/SQLite e nessuna attivazione o negoziazione automatica del gruppo v1.

Verifica locale: 16 nuovi test comuni (otto codec/otto decoder), suite protocollo **188 JVM/175 unit Android**, zero errori/fallimenti/skipped. Tutti gli split/byte singoli, frame consecutivi/tail incompleto, buffer, limiti esatti/oltre/uint32 alto, troncamento a ogni offset, errori sanitizzati, formati separati, versione/campi/ID/Base64 ostili. Il test esistente con due tentativi e P-256 JVM ora effettua encode/frammentazione/decode delle conferme prima della verifica. Metadata comuni e Android/desktop compilati; non Native/hardware o connessione TLS del nuovo gruppo. Wire 0/SQLite/identità/versioni/lock invariati.

## Bridge callback condiviso

`GroupAdmissionConfirmationBridge` possiede decoder e tentativo, senza esporli a mutazioni esterne. Il contesto deve provenire dalle offerte verificate del canale TLS selezionato; identità locale confrontata con quella TLS, pin remoto verificato dal tentativo. `prepare()` verifica la prova prima di esporre il confronto o accettare byte. Dati prima della preparazione sono un errore dell'adattatore e chiudono il bridge.

La UI mantiene il ticket di confronto corrente; `confirm` restituisce un ticket OS di firma, `signed` produce un ticket di scrittura con frame `GROUP_CONFIRM` e copia difensiva del buffer. Il callback di scrittura conserva **l'esatto ticket** e chiama `sent` soltanto dopo il completamento reale del trasporto. Ticket stranieri, già consumati o invalidati non avanzano il tentativo e non sostituiscono quelli correnti. `signingFailed` e `writeFailed` valgono solo per il ticket corrente.

`accept` ricompone i frammenti e inoltra le attestazioni al tentativo. Errori di frame, verifica, rientranza, EOF o eventi di ciclo di vita chiudono il tentativo e decoder, rilasciano i ticket e mantengono il primo motivo. EOF pulito revoca anche `Confirmed`; framing troncato è distinto come `InvalidFrame` e rilanciato. Se un batch contiene una coda malformata non si promuove dal prefisso valido. Il bridge non ignora errori/cancellazione dell'adattatore: chiude e rilancia. Le entry point potenzialmente fallibili dichiarano `@Throws(Exception::class)` per il futuro confine Apple; export/esecuzione Native di questa API non ancora attestati.

`state()` e `remainingMillis()` fanno applicare la scadenza del tentativo; `cancel`, `block`, `leaveGroup` e `transportFailed` invalidano il bridge. Il proprietario OS deve serializzare tutte le chiamate, inoltrare tali eventi, schedulare il timer anche quando inattivo e **chiudere realmente il trasporto quando osserva `Closed`**. Nessuna socket o task di timer è creata dal bridge. Non è un nuovo servizio di rete e non concede trust: fondazione/adozione radice, resolver certificati e completamento recuperabile/persistenza restano aperti.

Verifica locale finale: 12 nuovi test comuni di bridge, suite protocollo **200 JVM/187 unit Android**, zero errori/fallimenti/skipped. Ticket/buffer indipendenti, due ordini e dati frammentati, verifica prima dell'ingresso, pin locale/peer, EOF anche confermato e troncamenti, batch malformati/duplicati, fallimenti firma/write, eventi/callback tardivi, cancellazione durante prova o conferma, scadenza anche dopo conferma, errori/cancellazione propagati. Test P-256 esistente esteso a due bridge completi con nonce/ID fixture e clock monotono reale: prova, firme, framing e callback, **non TLS/OS/network/hardware**. Metadata comuni e Android/desktop compilati; unit Android su JVM, non Native.

Checkpoint concluso su `6e892e4`: [37776667526](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37776667526), successo Native dominio/protocollo/persistenza e 38 XCTest ordinari con zero fallimenti. Framework e app compilati. Nessuna nuova esecuzione dei tre bootstrap interop, nessun polling; simulatore, non hardware. Le diciture Native pendente nelle sezioni precedenti descrivono le evidenze storiche dei singoli incrementi.

## Verificatore certificati JVM/Android — 9 ottobre 2026

`GroupAdmissionCertificateVerifier` è un adattatore interno di connectivity, compilato in `jvmAndAndroidMain`. Fornisce il callback `(expectedIssuerPin, bytes, signature) -> Boolean` del verificatore di catena; il resolver deve fornire il certificato per quel pin, non una chiave per alias dichiarato dal peer. SHA-256 del DER deve coincidere esattamente: due certificati con stessa chiave ma DER diverso sono identità diverse. Controlla validità temporale attuale, parametri completi secp256r1 (non soltanto dimensione 256), autofirma e firma SHA256withECDSA sui byte canonici ricevuti dal core. Firma Base64 standard canonica, 4–256 caratteri prima di decodifica; DER/firma invalida rifiutata.

Certificato mancante/invalido o pin discordante restituiscono false. Eccezioni inattese del resolver/provider e cancellazione sono propagate, non nascoste dal `runCatching` del vecchio `Identity.verify`, che rimane invariato. Nessuna cache di certificati/esiti: ogni invocazione ricontrolla il resolver e la validità. Il resolver deve rispettare l'ownership seriale del futuro adattatore; eventuali blocchi/uscita/deadline restano governati dal tentativo e dal proprietario, non da una firma valida.

Non è un trust manager TLS, non recupera certificati dalla rete, non adotta radici né rende il firmatario membro autorizzato senza tutta la catena ancorata indipendentemente. Nessun chiamante nel servizio/app/UI/SQLite. La fornitura/distribuzione dei certificati e l'adattatore Apple restano aperti; fondazione/adozione confermata e commit recuperabile sono ancora necessari prima dell'attivazione.

Sette test JVM con certificati reali: percorso delegato e firmatario mancante, sostituzione anche stessa chiave, scadenza/futuro, curva/autofirma errata, byte/chiave/DER/Base64 invalidi, guasti/cancellazione propagati, pin malformato e mancata cache. Android/desktop compilati; non esecuzione Android/Apple/hardware o TLS gruppo al termine di quell'incremento. Comando/evidenze nella sintesi corrente di `STATO_SVILUPPO.md`.

## Connessione isolata delle conferme gruppo — 9 ottobre 2026

`GroupAdmissionConnection`, interno a connectivity `jvmAndAndroidMain`, possiede un socket TLS 1.3 già autenticato reciprocamente e selezionato per pin. Non è un nuovo nodo/servizio o un trust manager: `adopt` richiede le offerte fresche già verificate **su quello stesso canale**, il contesto congelato e la radice indipendente. Il trasferimento avviene anche in caso di errore: non si deve continuare a usare il socket esternamente. Nessun proprietario bootstrap o suo timer può rimanere attivo sul socket; il passaggio automatico da `HandshakeV1Connection` non è implementato in questo incremento.

Il certificato locale TLS deve coincidere con l'identità usata per firmare. Il bridge confronta il certificato remoto TLS con il peer selezionato e i ruoli del contesto. Snapshot di al massimo 32 certificati emittenti forniti dal chiamante, senza modifica concorrente durante la copia; i due certificati dei veri endpoint TLS prevalgono sulle eventuali voci ricevute per quei pin. Lo snapshot non è un elenco di membri autorizzati: ciascuna firma deve superare `GroupAdmissionCertificateVerifier` e l'intero percorso deve arrivare alla radice indipendente. Nessun resolver di rete/database è eseguito sotto il lock; verifica JCA sincrona su certificati già disponibili, limitata dalla catena. Il core ricontrolla deadline/stato dopo i callback, ma non interrompe internamente una chiamata del provider crittografico.

`prepare` verifica tutta la prova prima di esporre il confronto o leggere input. `comparison` restituisce il ticket corrente; la UI deve confrontare il codice completo e passare **quel ticket** a `confirm`. La firma locale avviene fuori dal lock di stato; il frame prodotto dal bridge viene scritto e flushato fuori dal lock. Soltanto il ritorno riuscito di entrambe le operazioni, seguito da un nuovo controllo dello stato, chiama `bridge.sent`. Write fallita, flush fallito o completamento dopo blocco/cancellazione/scadenza non attestano progresso. `Confirmed` rimane revocabile e non viene promosso a trust/appartenenza persistente.

Il chiamante guida `readChunk` su un worker I/O: un solo lettore alla volta, buffer massimo 1028 byte, timeout residuo impostato prima di ogni lettura. `true` può indicare un semplice frammento, non una conferma: si consulta lo stato tipizzato. Il bridge ricompone/valida i frame; EOF pulito chiude e revoca anche `Confirmed`, EOF troncato o dati malformati producono `InvalidGroupAdmissionFrameException` senza causa/contenuto peer. Errori inattesi e cancellazione propagati; primo motivo conservato. Anche un rifiuto che restituisce soltanto false/null fa osservare lo stato terminale e chiudere il socket.

`close`, `block`, `leaveGroup` invalidano ticket e socket. Tutte le chiamate al core sono serializzate dal lock di stato; read/write/firma non lo trattengono. Deadline originale di 120 s dalla selezione, non riavviata da `prepare` o dalla conferma; scheduler condiviso fornito dal chiamante, mai arrestato dall'owner. Il timer chiude anche socket inattivi o con read/write/firma in corso, senza necessità di interrogare la UI. Cleanup una sola volta, shutdown input e close entrambi tentati, SO_LINGER abortivo predisposto mentre il canale è ancora vivo. Errori di cleanup sono visibili/soppressi sul guasto primario, non impediscono il secondo tentativo di rilascio.

Verificato su Windows/JVM: **24 nuovi test connessione**, sette certificati e 20 regressioni bootstrap TLS, **51 riusciti, zero fallimenti/errori/skipped**. Socket mutual TLS 1.3 veri, certificati/pin/JCA reali, offerte HELLO trasmesse sul canale, prova delegata con fondatore offline; confronto/click espliciti simulati soltanto nei test. Coperti frammentazione byte per byte, due conferme/write, mappe mancanti/sostituite/buffer snapshot/limiti, pin e identità locali, malformed/UTF-8/formato bootstrap/tail, EOF anche confermato, replay e ticket precedenti, blocco/uscita/cancel, lettura bloccata, flush fallito/tardivo, deadline originale/idle/read/confermato, guasti clock/scheduler/inizializzazione/cleanup e cancellazione propagata. Compilazione Android/desktop riuscita; non esecuzione del nuovo trasporto su Android fisico/Mac/Apple, non mDNS o rete fisica.

Nessun chiamante nel servizio/UI o nuovo trust/SQLite, wire 0/identità/versioni/lock invariati. Scambio della prova/certificati e handover delle offerte/ownership, fondazione/adozione confermata, completamento distribuito recuperabile e adattatore Apple restano aperti prima dell'attivazione.

Revisione finale: `cleanupFailure` volatile conserva il guasto del rilascio anche quando eseguito dal task di scadenza; rimane leggibile dal chiamante senza alterare il primo motivo di chiusura. Aggiunta regressione con timer reale, socket chiuso e guasto osservato fuori dal task. Conteggio finale **25 connessione + 7 certificati + 20 bootstrap = 52 JVM riusciti**, zero errori/fallimenti/skipped; Android/desktop ricompilati dopo la modifica produzione. Nessuna nuova verifica hardware/Apple.

## Handover bootstrap → conferme gruppo — blocco locale del 9 ottobre

`ProtocolHandshakeAttempt.offersForGroupAdmission()` restituisce uno snapshot soltanto dopo un HELLO compatibile con identità corrispondente al certificato TLS selezionato, nello stato `AwaitingConfirmation(false)`. Prima di HELLO, durante firma/write/verifica, dopo APPROVE remota, `Ready`, cancellazione o scadenza non è disponibile. Le viste delle capability sono copie difensive; `observedAtMillis` conserva l'ultima osservazione monotona. Uno snapshot trattenuto non dimostra che il tentativo sia ancora vivo e non conferma l'ammissione.

`GroupAdmissionConfirmationContext.fromBootstrapOffers` deriva i ruoli dai due endpoint e dall'ultima dichiarazione della prova nel Kotlin condiviso. L'ordine locale/remoto non modifica emittente/destinatario o byte di confronto. Endpoint estranei, radice discordante e offerte incompatibili sono rifiutati dal contratto esistente; non vengono inventati altri nonce né adottata automaticamente `proof.anchor`. È ancora necessaria la verifica completa della catena mediante `prepare`.

`HandshakeV1Connection.transferToGroup(expectedAnchor, proof, issuerCertificates)` è l'ingresso di handover JVM/Android sullo **stesso** socket. Non accetta un contesto costruito con offerte di un altro tentativo. Un lock di ownership esclude le intere operazioni read/write/firma: l'acquisizione non aspetta I/O in corso, ma l'inizializzazione ricevente resta un'operazione da worker I/O, non da UI. Se il lock è occupato o la fase non è eleggibile, restituisce null e non trasferisce la risorsa. Il chiamante non deve avviare un'altra lettura bootstrap mentre decide il passaggio; non serve polling né reset del tentativo.

Durante il rilascio serializzato vengono cancellati il vecchio timer e i ticket bootstrap; la fase diventa `ReleasedToGroup` e il nuovo owner riceve socket, identità, pin selezionato, istante di selezione e scheduler originali. Il suo orologio rifiuta osservazioni anteriori al watermark e la deadline resta 120 s dalla selezione iniziale. Anche un callback del vecchio timer già accodato osserva la fase terminale senza leggere il clock, riprogrammarsi o chiudere il socket. Il vecchio `close` è intenzionalmente inefficace: da quel momento il chiamante deve arrestare **il nuovo owner** per annullare l'ammissione. Entrambi gli owner conservano lo scheduler condiviso senza arrestarlo.

`ReleasedToGroup` indica rilascio di ownership, non successo dell'inizializzazione o appartenenza. Errori di costruzione del contesto prima del rilascio invalidano e chiudono il bootstrap. Dopo il rilascio `GroupAdmissionConnection.adopt` possiede il cleanup anche se mappe/certificati/stream/scheduler/clock falliscono; l'eccezione è propagata e il vecchio owner non tenta un secondo cleanup. Una scadenza durante il passaggio può restituire un owner gruppo già `Closed`: va controllato il suo stato/esito `prepare`, mai considerata la sola restituzione come autorizzazione.

Non è una continuazione del vecchio `APPROVE` o una promozione da `Ready`: serve il nuovo confronto legato alla prova completa e la doppia `GROUP_CONFIRM` firmata. Un'APPROVE bootstrap accodata ma non ancora letta non può diventare conferma gruppo: il nuovo decoder la rifiuta e chiude. Nessun componente esterno può continuare a usare gli stream; l'owner della composizione deve coordinare la transizione sui due endpoint. La prova e i certificati emittenti sono ancora parametri locali: **lo scambio di rete non è implementato da questo blocco**, né fondazione/adozione della radice, commit recuperabile, integrazione Apple o attivazione del gruppo nell'app.

Verificato solo in locale: cinque nuove prove comuni e 12 integrazioni handover con TLS/certificati/P-256 reali Windows; frame/input frammentabili, confronti/azioni UI/clock/guasti soltanto nelle fixture. Due owner sullo stesso TLS completano la doppia conferma senza vecchi ticket; coperti trasferimenti simultanei, lettura in corso, vecchio timer già accodato, deadline originale, clock arretrato, APPROVE accodata, guasti di inizializzazione ricevente e cleanup unico. Comando aggregato riuscito: **205 protocollo JVM / 192 unit Android / 64 connettività JVM**, zero errori/fallimenti/skipped, metadata/Android/desktop compilati. Unit Android su JVM, metadata non Native, loopback non hardware. Nessun push, nuovo esito CI o collaudo fisico; evidenze correnti in STATO/PASSAGGIO.

Revisione finale dello stesso blocco: aggiunto il caso HELLO + `GROUP_CONFIRM` nello stesso record TLS. `HandshakeV1FrameStream` consuma esattamente il frame bootstrap senza un proprio read-ahead buffer; il successivo owner conserva i byte accodati sullo stream TLS e li valida soltanto dopo `prepare`. Anche una firma remota già accodata non sostituisce la conferma locale. Totale **13 nuovi handover**, **38 test connessione gruppo / 65 connettività JVM selezionati**, zero errori/fallimenti/skipped, ultimo comando 13 s. Le ultime modifiche sono solo test/documentazione; produzione/compilazioni del checkpoint aggregato invariate, nessun push/CI.

## Scambio evidence sul bootstrap TLS — 9 ottobre 2026

L'owner JVM/Android offre `sendEvidenceAndTransfer(expectedAnchor, evidence)` all'emittente e `receiveEvidenceAndTransfer(expectedAnchor)` al destinatario. Una sola evidence, dopo HELLO compatibile/TLS-bound e prima di APPROVE bootstrap. Entrambi richiedono una radice indipendente: non viene ricavata implicitamente dalla rete. Nessuna attivazione del servizio, UI, trust o SQLite; il formato wire 0 resta invariato.

Un lock esclusivo non bloccante esclude l'intera read/write/firma bootstrap fino al handover atomico. Se è in corso altra operazione, il metodo restituisce null senza sottrarre il canale. Gli stream già posseduti dal bootstrap vengono riusati. Durante lo scambio il confronto bootstrap non è disponibile; una sua vecchia conferma concorrente non può scrivere prima del rilascio e diventa inefficace dopo. Cancel e callback del timer non acquisiscono il lock I/O: interrompono anche una read bloccata. Il timer originale resta attivo durante parsing, write e flush; deadline e clock sono ricontrollati, senza nuova finestra di 120 secondi.

Il reader richiede esattamente `nextReadBytes`, massimo 4096: non consuma GROUP_CONFIRM accodata. Header/JSON/UTF-8 invalidi danno un errore fisso senza causa peer, EOF incompleto e zero progressi falliscono; DER/pin/ruoli/radice errati chiudono senza handover. La catena viene verificata nel nuovo owner con `prepare`, prima di confronto/input; nessun successo del trasferimento equivale a prova o appartenenza. Entrambe le firme di conferma e le effettive write rimangono necessarie, `Confirmed` non è commit del trust.

Sette nuove regressioni con TLS/P-256/JCA reali in loopback Windows coprono scambio effettivo, conferma accodata/doppio consenso, root mismatch, firma alterata, header/JSON/EOF/DER/ruolo ostili, cancel e callback timer su read bloccata con conferma bootstrap concorrente. Non Apple/Native/hardware. Comandi e conteggi in sintesi STATO; sezioni seguenti sono checkpoint precedenti.

## Formato evidence prova e certificati — 9 ottobre 2026, checkpoint locale precedente

`GroupAdmissionEvidenceCodec` definisce un envelope v1 isolato, non instradato dal servizio wire 0 o dal bootstrap corrente:

```json
{"version":1,"type":"GROUP_EVIDENCE","proof":{"version":1,"anchor":{"group":"…","founder":"…"},"admissions":["…"]},"certificates":[{"identity":"…","der":"…"}]}
```

Segnaposto illustrativi, non payload valido. `proof` riusa esattamente il serializer di `GroupAdmissionProofCodec`: stessa radice/path/versioni/firme/ordine, duplicati annidati ancora rifiutati. Il cambio di visibilità del serializer è interno al modulo, non un cambio del formato della prova. L'envelope ha quattro campi obbligatori, version numero JSON esattamente 1 e type stringa esattamente GROUP_EVIDENCE. Unknown/missing/duplicate anche escaped, tipi errati, JSON residuo e UTF-8 invalido rifiutati senza fallback ai formati precedenti.

Certificati pubblici di **tutti e soli** gli emittenti del percorso: includono il fondatore offline e l'emittente finale, non richiedono il certificato dell'ultimo membro senza delegazioni ulteriori. Copertura sintattica non verifica topologia o firme. Pin 64 hex minuscoli unici, ogni voce solo `identity` e `der`, nessun alias o chiave privata. DER trasportato come Base64 standard canonico, padding/bit finali controllati con scansione lineare limitata, senza regex ricorsiva o parser OS. Sintassi accettata non significa certificato X.509 valido. Codec ordina le voci per pin senza riordinare il percorso; DTO mantiene snapshot/viste difensive. La prova canonica già contiene i pin degli emittenti, e il DER è verificato rispetto a quei pin: l'envelope non introduce un nuovo dominio di firma né autorizzazione dalla sola presenza di certificati.

Limiti prima dei parser: **262144 byte** interi/depth **5**, **1–32** voci, **1–4096 byte DER** ciascuno (massimo 5464 caratteri Base64). Il limite comprende prova e certificati; non aumenta i limiti del codec prova standalone, HELLO o GROUP_CONFIRM. La 33ª voce viene rifiutata prima di decodificarla. Non si tronca il percorso. Il massimo canonico con 32 ammissioni/firme massime e 32 certificati massimi entra nel limite; whitespace/escape consumano il budget dell'envelope. Questi limiti non definiscono il numero di membri del gruppo.

`GroupAdmissionEvidenceFraming` usa uint32 big endian/4 byte, payload 1–262144, stessa sola primitiva di lunghezza degli altri frame. `GroupAdmissionEvidenceFrameDecoder` riceve chunk di al massimo **4096 byte**, valida l'intero header prima di allocare al massimo un payload, restituisce evidence soltanto quando completa e si chiude definitivamente su completamento/errore/cancel. EOF prima dell'evidence obbligatoria, anche senza byte, fallisce. Dopo completamento non va chiamato `finish` né riusato il decoder. JSON/UTF-8 malformati diventano `Invalid group evidence frame` senza causa/contenuti peer; errori inattesi propagati. Non è timer né proprietario del socket: il futuro owner deve inoltrare scadenza/cancel/blocco e chiudere il trasporto.

Il risultato contiene `consumedBytes`: eventuali byte accodati dopo la singola evidence **non sono né consumati né convalidati**. Restano nel buffer posseduto dal chiamante, che deve conservarli e instradarli solo nella fase corretta dopo verifica/handover; una seconda evidence non è un'altra ammissione autorizzata. `nextReadBytes` permette al lettore bloccante di richiedere solo header o payload residuo, massimo 4096, evitando il problema di read-ahead alla transizione. Nessun batch parziale o queue illimitata nel decoder; anche encoder/framing sono soltanto preparazione, non conferma di write.

`GroupAdmissionEvidenceCertificates.decode` interno JVM/Android usa CertificateFactory per un solo X.509 per voce, senza fallback PEM, reencoding discordante o byte/certificati aggiunti; hash dei byte DER ricevuti esattamente uguale al pin. Un errore atteso non restituisce una mappa parzialmente decodificata; diagnostica fissa senza causa. Provider/guasti inattesi non vengono nascosti. Restituisce **evidenza pubblica non verificata**, non trust: validità temporale, P-256 completa, autofirma e firme vengono ancora controllate da `GroupAdmissionCertificateVerifier`, intera topologia/radice indipendente dal core e entrambe le conferme dal tentativo. I certificati dei veri endpoint TLS continuano a prevalere nella composizione dell'owner.

Verifiche locali: casi comuni codec/framing/decoder per round-trip, limiti massimi, campi/duplicati, copertura, Base64 canonico, header uint32, frammentazione in ogni punto, EOF/cancel, copie e tail non consumato; test JVM confrontano Base64 col JDK per tutte le dimensioni 1–4096. Certificati reali: delegazione completa, pin sostituito anche stessa chiave, DER troncato/trailing/concatenato/PEM, niente esiti parziali; parsing non aggira validità/curva/autofirma. Due nuove prove TLS del handover con evidence decodificata fornita localmente: doppia conferma obbligatoria e prova alterata rifiutata senza confronto. Conteggi finali/comandi nella sintesi STATO. Non è ancora scambio di evidence sotto owner sul canale, Native/Swift/Apple o hardware; wire 0/schema/identità/versioni/lock invariati, nessun push/CI.

## Vettori pubblici delle conferme JVM → Apple — 11 ottobre 2026, locale

Continuazione locale: i test sui vettori sono ora **16 JVM e 16 XCTest preparati**. Sei ulteriori casi verificano EOF per ogni prefisso incompleto (305 del frame da 306 byte), nessuna verifica parziale per chunk con frame valido e coda malformata, invalidazione della firma pendente dopo EOF e della write dopo errore, revoca anche dopo Confirmed con primo errore preservato e non trasferibilità dei ticket fra istanze persino con byte identici. Nessuna nuova chiave/fixture o modifica di produzione. Selezione complessiva finale **70 JVM riusciti**, più **16 controlli host facciata riusciti**; i conteggi 64/10 sotto sono evidenze precedenti. I 16 XCTest locali non sono ancora compilati/eseguiti; non si attribuisce al verde remoto precedente copertura del codice locale. Dettagli/comandi nella sintesi STATO. Restano nove file locali, nessun commit/push/CI/polling; checkpoint Native/XCTest prima dell'integrazione servizio/trust.

`JvmGroupConfirmationVectors.swift` contiene soltanto materiale pubblico generato con il core Kotlin 2.1.21 e JDK 17/Bouncy Castle 1.83 già in cache: due certificati X.509 P-256 autofirmati SHA-256, pin esatti, proof originale e alternativa valida con firma ECDSA diversa sullo stesso claim, hash del confronto e di entrambe le approvazioni, firme/frame direzionali, firma della chiave sbagliata e firma valida del dominio bootstrap. Le chiavi private sono effimere e non sono mai esportate/salvate. Non sono identità app, credenziali TLS, root adoption o trust.

Dieci test JVM leggono i soli dati pubblici da questo stesso file Swift e usano core/JCA reali. Dieci XCTest equivalenti preparati riusano facciate e verifica Apple effettiva; clock, nonces, firme locali precalcolate e data calendario 2026-10-11 sono fixture, non un trasporto OS. Controllano doppia conferma e write ack, binding a nonce/proof/capability interi, rifiuto chiave errata/reflection/dominio bootstrap, normalizzazione JSON/feature equivalenti, bytewise senza callback crypto anticipato, duplicati che revocano Confirmed ed EOF/blocco. Valutare la firma alternativa come prova valida prima di rifiutare il vecchio consenso: non confondere replay del contesto con una catena invalida.

Verifiche: selezione `:protocol:jvmTest --tests '*GroupAdmissionConfirmation*'`, **64 JVM riusciti**, dieci nuovi; ulteriori **dieci controlli host JVM/JCA** sui quattro sorgenti facciata iOS effettivi compilati separatamente. Non nuovo Native/Swift/Apple/TLS/hardware, né test Android ripetuti per sorgenti comuni invariati. I dieci XCTest locali non sono compilati/eseguiti. Nessuna modifica produzione, identità, schema, wire 0, versioni/lock o workflow; nessun nuovo commit/push/dispatch/polling. Dettagli/comandi in sintesi STATO.

Il precedente blocco owner `15ee24a` è ora compilato dalla CI iOS rapida [38141323971](https://github.com/zanzaro-mirco/lantern-share/actions/runs/38141323971), inclusi i 28 XCTest nuovi, ma non eseguito in simulatore. Serve il checkpoint Native/XCTest prima del servizio/trust; questi vettori locali richiederanno una futura consegna raggruppata autorizzata. Il verde rapido non li copre e non sostituisce il collaudo fisico.

La fixture pubblica Swift è un input Gradle esplicito dei test JVM, con path sensitivity relativa; una modifica di sola fixture deve invalidare up-to-date/cache. Il planner CI seleziona entrambi i consumatori JVM+iOS per quel percorso preciso, senza modificare frequenza o modalità dei workflow. Nuova regressione planner e invalidazione locale fixture-only verificate: 12 test planner, 64 JVM, zero errori/fallimenti. Non è nuova CI remota.

## Scambio evidence e cessione OS Apple — 11 ottobre 2026, compilato in CI rapida

`HandshakeV1Channel` in modalità gruppo ferma il bootstrap al confine HELLO. `sendEvidenceAndTransfer` richiede ruolo emittente; `receiveEvidenceAndTransfer` ruolo destinatario, con radice attesa indipendente obbligatoria. Il Kotlin `IosGroupAdmissionContext` deriva il contesto dalle offerte opache originali; nessuna ricostruzione di nonce/capability/ruoli in Swift, adozione della radice ricevuta o vecchia APPROVE. Il Bool restituito indica soltanto l'avvio dello scambio, non scrittura completata o conferma.

Durante lo scambio bootstrap mantiene un solo read/write OS, timer originale e cancel/cleanup. Il decoder evidence riceve il budget esatto header/payload (chunk 4096); non legge GROUP_CONFIRM successiva, anche coalescente nello stesso write remoto. Controlli liveness prima dei read, dopo decoding/parse/write e al rilascio; contesto/radice/ruoli prima del lavoro DER. EOF o guasto chiudono senza cessione. Radice falsa, ruolo invertito, input ostile e certificato DER/pin invalido non pubblicano confronto o owner di gruppo.

Quando non vi sono I/O/firma pendenti, sulla stessa coda seriale si valida il contesto corrente, si rilascia il core con watermark finale e si rende terminale il vecchio owner OS. Timer/decoder/handler vecchi rimossi; callback già accodati/start/cancel/deinit non toccano più NWConnection. `GroupAdmissionChannel` assume risorsa e cleanup anche se il suo inizializzatore fallisce: nessun fallback al bootstrap o doppia chiusura da parte sua. Il chiamante di onTransferred deve trattenere il nuovo owner e chiamarne start; nessuna risorsa raw è pubblicata. Se non lo trattiene, deinit chiude il canale.

`IosGroupAdmissionConfirmation` riusa bridge/attempt/framing/ticket comuni. selectedAt è quello prima del TLS e il clock non può tornare sotto il watermark ceduto; nessun budget ripristinato. Il nuovo owner congela i certificati ricevuti, sostituisce i due endpoint con quelli effettivi TLS e riusa pin/date/P-256/autofirma SHA-256/verifica OS già testati. start/prepare verifica **tutta** la prova prima di input e confronto completo SHA-256. Conferma con ticket corrente, firma OS fuori coda, write e contentProcessed effettivamente riuscito prima di sent. Due firme del contesto gruppo necessarie; nessuna promozione da confronto, parsing, catena offline o firma accodata.

Timer resta attivo anche senza start, durante firma/read e dopo CONFIRMED. EOF/errore/cancel/blocco/uscita/deadline invalidano anche questo progresso, senza trust persistente. Callback rete non sovrascrive expiry/clock già raggiunti; guasti inattesi restano adapter failure e diagnostica non include testo del peer. Nessun servizio/UI wire 0, chat, root adoption o database coinvolto. Le sezioni locali seguenti descrivono gli incrementi intermedi precedenti, non le nuove limitazioni di ownership.

Verificato su Windows: 50 JVM/50 unit Android comuni mirati, zero fallimenti/errori, 30 smoke JVM sulle quattro facciate effettive, inclusa prova/doppia firma P-256 JCA reale con pin fixture. **18 XCTest nuovi preparati**, non compilati/eseguiti: sette facciata e undici integrazioni/confini TLS Apple (doppio consenso/deinit, deadline ceduta e read bloccata, cancel, root/ruolo/firma, coalescenza, input/EOF, block/firma tardiva, init ricevente fallita/cleanup). L'ultimo usa offerte core fixture ed endpoint deliberatamente errato su TLS reale; nessun owner bootstrap OS vivo viene affiancato. Totale locale 28 con i dieci precedenti. Nessun nuovo Native/export/Swift/OS/hardware attestato; il checkpoint remoto 57 XCTest del vecchio commit non copre questo blocco. Prossimo passo: compilazione/checkpoint Apple prima del servizio/trust, senza push o CI ora richiesti, nessun polling. Versioni/lock/identità/schema/wire 0 invariati.

## Storico locale — offerte e rilascio del core callback

`ProtocolHandshakeBridge.offersForGroupAdmission` riusa lo snapshot dell'Attempt soltanto in fase Active, senza ticket firma/write e con decoder **al confine di frame**. Un header anche di un solo byte impedisce rilascio: il solo budget 4 non dimostra un confine. `releaseForGroupAdmission` ricontrolla lo stato corrente, restituisce offerte con watermark finale e passa una sola volta a `ReleasedToGroup`; decoder/ticket/tentativo sono invalidati. Vecchie operazioni/bootstrap timer che consultano il core non leggono più il clock, non generano nuove firme/write e non riattivano lo stato. Snapshot precedentemente trattenuto non sostituisce la verifica liveness all'atto del rilascio.

La facciata `IosHandshakeV1Offers` mantiene offerte/nonce/capability nel Kotlin condiviso, senza ricostruirli in Swift. Questo rilascio **non trasferisce socket, timer o cleanup**: il chiamante OS futuro dovrà escludere ogni receive/send/firma pendente e collegarlo atomicamente alla cessione. Il canale Apple attuale non chiama ancora release e continua a possedere NWConnection anche nella pausa. Non esporre la risorsa a un altro lettore finché l'ownership OS non è trasferita; il ricevente dovrà conservare deadline/watermark, controllare ruoli/radice indipendente e verificare l'intera prova prima del confronto/doppia conferma.

Tre regressioni comuni aggiunte: 25 JVM/25 unit Android e metadata comuni riusciti, 23 smoke JVM sulle facciate effettive; due XCTest di confine release preparati, non compilati/eseguiti. Nessun nuovo Native/Swift/OS attestato, servizio/wire 0/trust/schema/identità/versioni/lock invariati, nessun push/CI intermedio. Prossimo incremento: scambio evidence e cessione OS Apple collegati al release del core.

## Storico locale — pausa Apple al confine HELLO

`ProtocolHandshakeFrameDecoder.nextReadBytes` offre il residuo esatto di header/payload senza modificare la precedente API batch. Il bridge offre il budget soltanto dopo HELLO write completata, osservando liveness/deadline; la facciata iOS lo esporta come funzione fallibile `@Throws`. `HandshakeV1Channel` richiede non più di tale budget a Network.framework: il frame della fase successiva non viene consumato dal decoder bootstrap.

La continuazione default `.approvals` mantiene il precedente percorso. `.groupAdmission(onHello:)` ferma le receive dopo il primo HELLO compatibile, pubblica una sola callback, non il confronto bootstrap, e impedisce APPROVE anche nei callback UI reentranti. Non esiste ancora un destinatario di ownership: bootstrap mantiene connessione, timer e cleanup; cancel/EOF/errore/deadline/deinit continuano a chiuderla. Una pausa non autorizza a leggere la connessione da un altro oggetto. Dopo la futura cessione, invece, questi cleanup vecchi dovranno essere disattivati atomicamente.

Verifica locale: quattro regressioni comuni nuove, 22 JVM/22 unit Android riusciti e metadata comune compilato; 22 smoke JVM sulle facciate effettive. Due XCTest TLS reali aggiunti ma non compilati/eseguiti per HELLO+tail coalescenti, cancel e deadline originale nella pausa. Nessun Native/Swift/OS nuovo attestato; servizio wire 0/trust/identità/schema/versioni/lock invariati. Prossimo incremento: scambio evidence e handover dalla pausa, senza doppio owner o reset della deadline.

## Storico locale — framing evidence Swift-facing

Il checkpoint del commit `9cf1703` è riuscito: 57 XCTest, inclusi tutti i 19 certificati/evidence, zero fallimenti. Dettagli in sintesi STATO; non certifica le modifiche framing successive né hardware.

`IosGroupAdmissionEvidence.framedBytes()` delega encoding/framing comuni e restituisce una copia, non un completamento write. `IosGroupAdmissionEvidenceDecoder` è una facciata senza risorse OS: esporta il chunk massimo, `nextReadBytes()` fallibile, `accept` con `consumedBytes`/evidence nullable, EOF e cancel. Si usa sulla coda seriale dell'owner; `@Throws` protegge anche il budget come funzione, non come getter che può fallire senza bridge NSError. Riusa limiti, copie, errori e terminalità del decoder Kotlin senza duplicare JSON, header o regole in Swift.

Il budget esatto evita read-ahead **soltanto se il chiamante lo rispetta**; un chunk coalescente conserva il tail presso il chiamante. Non concede ownership, non cancella una receive pendente, non trasferisce NWConnection, timer o autorizzazioni. Un singolo risultato completo non permette altri frame; errori/EOF/cancel sono terminali. Il futuro owner deve ancora realizzare la transizione sicura da HELLO, liveness/deadline e instradamento successivo. Servizio/trust/schema/identità/wire 0 invariati.

Verifiche locali: 21 smoke JVM sulle facciate effettive, sette nuovi framing/decoder; sei XCTest preparati ma non compilati/eseguiti. Non nuovo Native/export/Swift/OS/TLS gruppo; nessun push/CI intermedio. Prossimo incremento: ownership della transizione Apple bootstrap → evidence, prima di attivare gruppo/conferme.

## Storico — adattatore certificati evidence Apple

La facciata `IosGroupAdmissionEvidence` riusa il codec condiviso per il payload, esporta viste difensive dei soli certificati e i limiti già definiti. JSON/UTF-8 malformato restituisce errore fisso senza causa peer. `verifyChain` delega al verificatore Kotlin dell'intera prova: gruppo/fondatore/destinatario **attesi e indipendenti**, struttura completa prima dei callback, byte canonici dal core, nessuna appartenenza parziale o errore callback convertito in successo. Il booleano di esito indica soltanto verifica offline, non conferma o autorizzazione.

`ApplePublicCertificate.decode` riceve DER già limitato dal chiamante e controlla prima un unico oggetto DER rigoroso con [SwiftASN1 1.3.0](https://github.com/apple/swift-asn1/blob/1.3.0/Sources/SwiftASN1/ASN1.swift), senza BER/PEM/trailing bytes. Poi usa [Security](https://developer.apple.com/documentation/security/storing-a-der-encoded-x-509-certificate) per X.509, richiede `SecCertificateCopyData == bytes ricevuti` e SHA-256 dello stesso DER == pin. Solo errori ASN1 attesi diventano diagnostica fissa senza causa; guasti inattesi propagati. SwiftASN1 è già dichiarato/vincolato nel package: aggiunta soltanto la dipendenza esplicita al target che lo importa, nessuna nuova libreria/versione/lock.

`GroupAdmissionEvidenceCertificates.decode` non restituisce una mappa se una voce fallisce. `verifyChain` usa uno snapshot di tali certificati e la policy Apple esistente, ricontrollando pin, date, P-256, autofirma ECDSA/SHA-256 e firma dei byte canonici. Data di verifica esplicita solo per i test, nessuna cache o acquisizione di trust. Non salva chiavi/certificati nel Keychain né credenziali SQLite. Parsing/hash non attestano validità crittografica; una catena verificata non attesta TLS o consenso.

Non esistono ancora owner/handover/timer gruppo Apple o chiamanti nel servizio/UI. Il futuro owner deve vincolare i certificati effettivi dei due endpoint TLS (che prevalgono su quelli ricevuti), le offerte fresche, la radice indipendente e la deadline originale; richiedere entrambe le conferme; ricontrollare blocchi/cancel/uscita prima del commit recuperabile. Niente promozione dal solo booleano o `Confirmed`.

Vincoli riscontrati nella revisione del proprietario Apple attuale, da risolvere **nel futuro incremento di handover**, non nel parser certificati: `HandshakeV1Channel.receiveNext` riavvia una receive dopo HELLO e il decoder bootstrap consuma l'intero chunk/batch. Non può ricevere HELLO + evidence e poi recuperare i byte già instradati al decoder sbagliato; una read già pendente non va affiancata a un secondo owner. Serviranno budget di lettura esatti o un instradamento del tail esplicitamente posseduto e una transizione prima di riavviare la receive. Inoltre il `deinit` corrente chiude sempre NWConnection: dopo un rilascio dovrà rispettare la ownership ceduta, come dovranno fare timer/callback/close già accodati. Conservare istante di selezione e watermark monotono, senza un nuovo budget di 120 s. Minimo collaudo successivo: HELLO/evidence/conferma coalescenti, read/firma in corso, vecchio timer/deinit dopo rilascio, cancel/deadline e cleanup ricevente. L'attuale bootstrap resta proprietario esclusivo; nessun handover Apple è dichiarato implementato.

Verifica disponibile: sorgente della facciata compilato separatamente come JVM con Kotlin 2.1.21, 14 smoke check locali riusciti; uno usa P-256/JCA reale con pin/DER fixture, non verifica Apple o certificati. Preparati **19 XCTest** per dati/diagnostica/limiti, DER rigoroso, pin/key substitution, mappa senza esiti parziali, catena delegata Apple con radice indipendente, validità/autofirma/firma finale e confine callback Swift. Tre vettori pubblici fissi in `JvmGroupAdmissionVectors.swift` sono prodotti da JDK 17/Bouncy Castle 1.83 già vincolati, firme claim sui byte canonici Kotlin; nessuna chiave privata conservata o trust creato. Verificati sul sorgente Swift effettivo in JVM: P-256/SHA-256 valido, P-384 e autofirma SHA-384 validi crittograficamente ma incompatibili con la policy Lantern. I test Apple devono distinguere il rifiuto di policy dalla firma claim errata; date fisse rendono i vettori indipendenti dal calendario dell'esecuzione. **XCTest non ancora compilati/eseguiti**, nessun export Native o hardware attestato; task metadata iOS SKIPPED su Windows. Il checkpoint 37952903588 riuscito riguarda il precedente commit 4511065, non questi nuovi sorgenti. Push ora autorizzato; prima CI rapida, poi checkpoint Native/Swift/XCTest da conclusa, senza dispatch duplicati o polling, prima del proprietario Apple.
