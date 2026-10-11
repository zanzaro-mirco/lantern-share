# ADR 010 — fondazione locale persistente

Data: 11 ottobre 2026. Implementazione locale; verifica Native e integrazione nel servizio ancora aperte.

## Decisione

La fondazione è distinta dall'ammissione remota e dal trust TLS. `LocalGroupRepository` nel dominio espone lettura della radice locale e inserimento atomico solo se assente. Il contratto non viene aggiunto a `DeviceRepository`: i consumatori PoC e gli adattatori di test esistenti non devono fingere supporto ai gruppi.

SQLDelight schema **2**, migrazione additiva `1.sqm`: tabella `local_group` con chiave singleton vincolata a 1, gruppo e fondatore. Nessuna modifica/distruzione di `trusted`, `setting` o `message`. Non si codifica l'appartenenza dentro il nome dispositivo, non si costruiscono credenziali autoreferenziali e non si adotta una radice ricevuta.

La scrittura è un unico `INSERT … SELECT … WHERE NOT EXISTS`, seguito da `changes()` nella stessa transazione/connessione. Il primo statement è una scrittura, non una lettura seguita da REPLACE: due driver indipendenti non possono entrambi creare/sostituire il gruppo. Zero inserimenti significa gruppo già presente, anche se identico. Vincoli e guasti I/O non vengono soppressi; un'origine corrotta non viene rigenerata.

Il driver desktop esegue la migrazione e aggiorna `user_version` nella stessa transazione, senza ricreare il database. Android e iOS utilizzano la migrazione generata tramite i driver SQLDelight esistenti; esecuzione nativa non attestata su questo host. Versioni future rifiutate dal desktop senza downgrade. L'apertura/migrazione va mantenuta sotto il proprietario unico del database; il test di concorrenza riguarda scritture su driver già inizializzati, non migrazioni simultanee.

## Ownership e identità

`GroupFoundationAttempt.commit()` mantiene la stessa regola nel Kotlin comune, usando soltanto il contratto di dominio, non driver o API OS. `LocalGroupFoundation` JVM/Android collega tentativo condiviso, identità esistente e SecureRandom; l'owner Swift omonimo usa la facciata `IosLocalGroupFoundation`, AppleIdentity esistente e SecRandomCopyBytes. `commit()` ricontrolla il contesto, consuma il ticket, e restituisce Committed soltanto dopo il ritorno della transazione. Una corsa con un altro inserimento restituisce AlreadyInGroup senza overwrite. Cancel/uscita antecedenti impediscono persino la lettura del database; un guasto dopo handoff propaga l'errore e non consente il replay del ticket. Un errore nella lettura preliminare non ha ancora ceduto ownership; una conferma di scrittura incerta impone invece recupero dallo stato durevole, mai replay.

La facciata Apple espone snapshot/ticket opachi, lettura immutabile della radice salvata e risultati di commit espliciti. Nessuna API pubblica espone direttamente l'inserimento di una radice arbitraria. Swift non ricrea stati, identificatori da UUID o regole di appartenenza: genera 32 byte OS soltanto quando Kotlin richiede casualità. Errore OS restituito come null al callback non-throwing → chiusura terminale Kotlin e rilancio dell'errore originale da Swift, senza fallback/retry. Cancellazione/reentrata durante quel callback non riattiva la richiesta. `leaveGroup` su questo owner invalida soltanto la richiesta: non implementa l'uscita durevole.

L'identità OS non è un dato SQLite: **non si promette atomicità distribuita fra Keychain/Keystore e database**. Il futuro servizio deve serializzare richieste, lettura dell'identità corrente, cambi di identità, cancellazione e commit sincrono, fuori dal thread UI. Il repository ricontrolla l'identità del fondatore rispetto a quella fornita dentro la transazione e arbitra l'assenza di appartenenza. Non accetta come autorità un pin di rete. Nessun codice di servizio/UI chiama ancora questo percorso.

Dopo errore, prima di una nuova richiesta esplicita si rilegge lo stato durevole. La sola tabella non abilita peer, chat o sessioni e non completa l'ammissione distribuita recuperabile. Uscita persistente e adozione remota sono incrementi separati. Owner Apple implementato localmente, non ancora verificato con Native/export/Swift/runtime: non attivarlo nel servizio prima del checkpoint pertinente.

## Verifica

SQLite JDBC reale: riapertura, identità discordante, due connessioni concorrenti, guasto tramite trigger SQLite prima e dopo INSERT, connessione in sola lettura, migrazione dal vecchio schema con nome/trust/messaggio/ricevuta preservati, origine corrotta, migrazione fallita senza reset, versione futura senza downgrade.

Owner JVM con identità/firme OS e SQLite reali: commit e riapertura, richieste concorrenti, cancellazione/uscita, identità/ticket estranei, errore senza replay e nuova richiesta, inserimento fra snapshot e scrittura, cancellazione durante la lettura. Le sole callback di interleaving/errore sono fixture di test; nessun adattatore simulato in produzione.

Undici regressioni comuni del commit, incluse lettura fallita prima dell'handoff, conferma incerta dopo scrittura e cancellazione tardiva. Quattro nuovi test Native iOS di riapertura/rifiuto della sostituzione, migrazione, guasto prima/dopo INSERT e sola lettura; undici XCTest del confine Kotlin/Swift e dell'owner con Keychain/SQLite/casualità OS predisposti, **non compilati/eseguiti su Windows**. Dieci scenari della facciata Kotlin effettiva compilati/eseguiti su JVM con JDBC reale e fixture del solo confine IosPersistence: non verificano la classe IosPersistence reale, Native, export o Swift. Evidenze effettive e limiti in `STATO_SVILUPPO.md`; collaudi fisici fase 1 obbligatori.
