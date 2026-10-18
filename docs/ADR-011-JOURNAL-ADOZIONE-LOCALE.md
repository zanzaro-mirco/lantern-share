# ADR 011 — deposito locale dell'adozione candidata

Data: 14 ottobre 2026; integrazioni 17–18 ottobre. Stato: implementati formato, deposito, ispezione non distruttiva e continuazione viva revocabile nel core; recovery e adozione non implementati. Ponte Apple dell'ispezione verificato nella CI e nel simulatore, non su hardware.

## Contesto

Il destinatario può completare il confronto della radice candidata e le due firme, ma non deve diventare membro dalla sola presenza di quei byte. Un arresto può interrompere le operazioni successive. Servono materiale storico completo e una scrittura locale recuperabile, senza ricostruire consenso o autorizzazione da un booleano.

## Decisione

Separare tre responsabilità:

1. `GroupRootAdoptionJournal` e il suo codec in protocol: payload versionato, bounded e non attendibile, con proof/evidence, offerte originali e firme. Specifica binaria in AMMISSIONE_GRUPPO.
2. `PendingGroupAdoption` e `GroupAdoptionJournalRepository` in domain: un record opaco con ID tentativo, identità locale/remota, radice candidata e byte difensivi. Nessuna dipendenza dal codec, SQLite o API OS.
3. SQLDelight e repository di piattaforma: deposito transazionale, rilettura e rimozione condizionale. Nessuna decisione crittografica o di recovery nel driver.

Il futuro owner deve generare un nuovo ID tentativo OS da 256 bit, rappresentato con 64 hex minuscoli, senza riciclare un ID precedente. È un identificatore di operazione, non un nuovo pin o una modifica alle identità esistenti. La sua generazione non è introdotta dal deposito.

### Schema 3, migrazione additiva

`2.sqm` aggiunge `group_adoption_journal`. Il singleton ammette un solo candidato pendente per installazione. Metadati obbligatori, payload BLOB fra 1 e 524288 byte. Questo è un budget di storage, non la versione/il limite del payload protocollo (v1, massimo 278901 byte). Nome, trust PoC, messaggi, ricevute e fondazione preesistenti non vengono riscritti.

Gli opener esistenti usano `LanternDatabase.Schema`: nessun percorso di reset o rigenerazione e nessuna nuova libreria. JDBC migra dentro la transazione esistente e rifiuta versioni future; un errore anche nella seconda migrazione conserva versione e dati precedenti. Gli adapter Native/Android continuano a usare gli opener SQLDelight già configurati; le nuove prove Native sono predisposte, non dichiarate eseguite su Windows.

### Contratto delle operazioni

- Lettura: assenza → null. Righe multiple, singleton/metadati non canonici, tipo o dimensione del BLOB invalidi → errore, non assenza. I byte restano opachi: una versione del codec sconosciuta o una firma invalida richiede controllo successivo, mai cancellazione automatica.
- Stage: controllo dell'identità OS corrente fornita dal caller; INSERT condizionale su assenza di journal e gruppo locale. True soltanto per inserimento committato; false soltanto per retry byte-per-byte e metadati identici. Un conflitto o un gruppo già presente genera errore e non sostituisce nulla. Query e ricontrolli nella stessa transazione; errori prima/dopo INSERT causano rollback.
- Rimozione: DELETE vincolato a tutti i metadati e al payload esatto osservato. Un callback obsoleto non elimina un record differente; false significa assente/diverso. Errori dopo DELETE causano rollback. Nessun trust o gruppo viene rimosso.

**Lo stage non prenota l'appartenenza.** Una successiva fondazione locale può riuscire: non si cambia il contratto già attivo del fondatore. Il futuro owner deve arbitrare la transizione definitiva e ricontrollare gruppo/identità/blocco/uscita; un record pendente non prevale sulla radice durevole. Non vengono aggiunti trigger che autorizzano peer o bloccano la UI di fondazione.

I repository JVM/Android serializzano con il lock già esistente; iOS usa lo stesso NSLock del repository. Il caller deve eseguire I/O fuori dalla UI, serializzare lifecycle e cambi di identità e mantenere il driver vivo fino al drain. Non si eseguono callback di rete/firma dentro queste transazioni. Un errore non autorizza replay automatici.

## Confine di sicurezza

I metadati del deposito non sono autenticati e il repository non garantisce che corrispondano al payload. Prima di usare il materiale, il futuro recovery deve:

1. Decodificare con limiti/versione senza trasformare errori in assenza.
2. Incrociare identità locale OS, metadati, ruoli, radice e dichiarazione finale.
3. Verificare DER esatto, pin, curva, validità e policy OS di tutti i certificati, inclusi i due endpoint.
4. Verificare l'intera catena e entrambe le firme direzionali sui byte ricostruiti.
5. Applicare stato durevole e policy di recovery, con ricontrolli prima di qualsiasi futuro commit.

Neppure il successo di tutti i controlli crittografici costituisce consenso corrente, selezione TLS o prova di commit distribuito. Non si ripristina la deadline monotona del vecchio processo e non si usa la radice ricevuta come trust indipendente. Nessun record abilita peer, messaggi, cronologia pregressa o sessioni.

### Ispezione storica di sola lettura

`GroupRootAdoptionJournalInspection` riceve uno snapshot `PendingGroupAdoption`, l'identità corrente letta dall'OS e un verificatore OS di certificati/firme. Prima decodifica bounded/versionata, poi incrocia identità locale, peer e radice dei metadati con i ruoli del payload. Prima di qualsiasi crittografia rifiuta mismatch; verifica quindi tutte le deleghe e le due approvazioni direzionali sui byte ricostruiti. L'ID tentativo resta metadato non autenticato, non è aggiunto ai byte firmati e non viene considerato prova di autenticità.

Risultati tipizzati distinguono identità cambiata, metadati incoerenti, catena invalida, firma locale/remota invalida e `HistoricalSignaturesValid`. Quest'ultimo significa soltanto firme storiche valide sotto la policy OS corrente: non è `Confirmed`, ticket di commit o decisione di recovery. L'ispezione non legge il gruppo durevole, blocco o uscita e può avere esito crittografico positivo anche quando una fondazione successiva prevale sul candidato. Il futuro owner deve applicare tali controlli e ricontrollare il record esatto prima di qualsiasi modifica. Identità/lifecycle serializzati dal caller; nessuna validità continua dopo il ritorno della funzione.

Errori di sintassi/versione/UTF-8 diventano `InvalidGroupRootAdoptionJournalException` con diagnostica fissa, senza contenuti o cause del parser. Non diventano assenza, cancellazione del record o semplice firma invalida. Il catch è limitato al decode: errori OS inattesi e cancellazioni del verificatore propagano invariati. DER/pin malformati restano errori dell'adattatore; certificati fuori policy o firme non valide restituiscono il fallimento crittografico. Nessuna transazione contiene callback crittografici.

JVM/Android riusano `GroupAdmissionEvidenceCertificates` per il DER esatto anche del membro e `GroupAdmissionCertificateVerifier` per pin, validità, curva, autofirma e firma. Mappa di certificati soltanto per la singola chiamata, nessun risultato di validità conservato fra ispezioni. iOS usa `IosGroupAdoptionJournalSnapshot` opaco e `IosPersistence.pendingGroupAdoption()` con `@Throws`; `fromStoredRecord` importa metadati/byte non attendibili senza scritture. Swift riusa `ApplePublicCertificate`, non replica codec o regole. Poiché il callback Kotlin non può lanciare errori Swift, l'adattatore conserva l'errore originale e lo rilancia prima di pubblicare il risultato temporaneo. Il progetto Xcode include il nuovo sorgente; nessun caller di servizio/UI/owner lo esegue ancora.

### Continuazione viva revocabile — 18 ottobre

`GroupRootAdoptionAttempt.handover` confronta il record completo con il journal canonico
ricostruito dalle due conferme del tentativo vivo, le sue offerte originali e l'evidence/DER
degli endpoint forniti dall'owner. Rilegge identità/gruppo locale tramite il preflight esistente,
ricontrolla liveness e trasferisce una sola volta lo stesso motore di conferma a
`GroupRootAdoptionHandover`. Il percorso legacy `releaseForCommit` rimane compatibile:
rilascio e handover si escludono. Nessuna scrittura o attestazione dello stage.

Il nuovo owner deve fornire certificati legati al TLS corrente e un ID tentativo OS fresco;
il core verifica il binding byte-per-byte, non DER/firme locali aggiuntive o casualità dell'ID.
Il journal può essere costruito dai messaggi direzionali originali raccolti sul canale;
non si richiama prima `releaseForCommit` per ottenerlo, perché consumerebbe il tentativo.
Mismatch del materiale genera errore senza consumare il confronto vivo; errori DB e revoche
mantengono il comportamento fail-closed del preflight.

La continuazione conserva deadline e watermark originali, espone stato/scadenza e confronto
esatto del record, riceve cancel/blocco/uscita/EOF. Non espone operazioni per firmare, ricevere
altre conferme o autorizzare un commit. Il vecchio owner diventa terminale e i suoi callback
non toccano la continuazione: caller OS responsabile del trasferimento serializzato di
socket, timer e routing lifecycle, ritirando i callback precedenti. Nessun nuovo timeout.

`matchesRecord` è solo un confronto dello snapshot mentre vivo, non legge SQLite e non
riserva il record. Draft/record trattenuti dopo revoca non ricreano permessi. Il futuro
commit richiede arbitrazione atomica, identità OS/gruppo/blocco/record e liveness ricontrollati.
Questo incremento non collega gli owner JVM/Swift, il servizio o la UI, e non adotta una root.

## Verifica e conseguenze

Test comuni di codec/binding/copie/limiti, firme P-256 reali, JDBC con riapertura, retry/conflitti fra connessioni, inserimento/rimozione falliti, storage corrotto/sola lettura e migrazioni 1→3/2→3. Integrazione TLS reale: firme raccolte sul canale, payload salvato in SQLite e riletto dopo chiusura/riapertura, pin/catena/entrambe le firme verificati; destinatario ancora senza gruppo/trust/storia. Una versione payload ignota rimane depositata dopo decode fallito.

Tre test Native iOS predisposti per riapertura/retry/rimozione, migrazione 2→3 preservativa e rollback su errori prima/dopo INSERT e dopo DELETE. La fixture preesistente della migrazione 1→corrente rimuove entrambe le nuove tabelle per rappresentare davvero lo schema 1. Risultati e comandi effettivi in STATO; predisposizione non equivale a runtime Native o hardware.

Nessun owner/caller attivo salva questi record ancora: il percorso TLS di deposito è una fixture di integrazione, ora estesa al trasferimento/revoca della continuazione. Nessuno stato distribuito, nuova fondazione remota, UI recovery, rotazione di identità o wire modificato. Nuove prove comuni, P-256/JCA e TLS/SQLite coprono l'ispezione; i sette XCTest dell'ispettore Apple sono passati nel checkpoint 38981050486 (141 totali), non su hardware. Il prossimo incremento collega il trasferimento revocabile all'owner JVM/Android e alla sua durata di risorse; non introduce ancora un commit locale. Il journal storico non può sostituire il confronto vivo. Risultati della nuova continuazione in STATO.
