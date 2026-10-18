# ADR 012 — punto di commit e interruzioni dell'ammissione

Data: 18 ottobre 2026. **Stato: politica A confermata esplicitamente dall'utente;
implementazione locale e test JVM/Android riusciti, checkpoint Apple nuovo pendente.**
Schema 4 additivo; nessun nuovo messaggio wire. B1 è verificato nel
checkpoint iOS completo `ea25221` / [39141932749](https://github.com/zanzaro-mirco/lantern-share/actions/runs/39141932749):
Native, framework/export, app e 151 XCTest in simulatore riusciti; nessun collaudo fisico.
B2 è collegato agli owner isolati, non ancora al servizio/UI; non è chiuso prima del
checkpoint Native/Swift/simulatore. Nessuna nuova verifica fisica.

## Problema concreto

`GROUP_CONFIRM` attesta l'approvazione del contesto firmato, non una scrittura SQLite.
Il suo completamento locale e la ricezione remota non sono simultanei: il destinatario
può avere entrambe le firme e risultare `Confirmed` mentre l'emittente è ancora in
`Sending(true)`, oppure si blocca/si arresta prima del proprio callback `sent`.
Una write riuscita non dimostra nemmeno che il peer abbia ricevuto/verificato i byte.

La regressione mantenuta
`GroupAdmissionConnectionTest.rootConfirmedDoesNotProveIssuerCompletionAndJournalCannotResumeConsent`
riproduce il primo caso con TLS reciproco/P-256 reali: ritarda soltanto il ritorno del
flush emittente dopo la write effettiva. Il membro passa alla continuazione e deposita
il journal; l'emittente si blocca prima di `sent`, il membro osserva EOF/errore e perde
il consenso vivo. Dopo riapertura SQLite, le firme storiche restano valide ma gruppo,
trust e cronologia restano assenti. Clic e ritardo sono fixture, non una nuova UI.

Il journal di ADR 011 non contiene una decisione durevole di ammissione. Non può essere
promosso ad appartenenza al riavvio, nemmeno se tutte le firme sono valide. Gli owner
attuali rifiutano ogni byte dopo l'handover: non esiste già un canale di commit/recovery.

## Invarianti comuni alle opzioni

- Nessuna promozione da discovery, catena coerente, `Confirmed`, handover o stage isolati.
- Prima del punto di commit: consenso vivo dello stesso tentativo, identità OS attuale,
  radice/destinatario/credenziale esatti, gruppo assente e blocco/uscita ricontrollati.
  La deadline originale non riparte. Revoche e cambi identità sono serializzati dal
  medesimo owner; uno snapshot precedente non costituisce una prenotazione.
- Lo storage arbitra nella stessa transazione assenza di appartenenza/fondazione e
  record completo esatto. Nessun callback di rete, firma o UI dentro il lock SQLite.
- Un eventuale commit salva atomicamente radice adottata, identità locale, prova e
  certificati necessari alla futura delega, più la sua identità di operazione. Non
  riusa `foundLocalGroup`: quel contratto è riservato alla fondazione locale.
- Fondazione e adozione non possono produrre due gruppi concorrenti. Una futura
  migrazione è additiva (3.sqm, schema 4) e conserva dati e journal schema 3.
  Lo storage del journal resta non fidato.
- Pubblicare appartenenza solo dopo commit riuscito. Un errore dal risultato ambiguo
  richiede rilettura dell'esatto esito durevole, non retry cieco, cancellazione del
  journal o successo dedotto dalla firma. Retry diversi non sostituiscono dati.
- Dopo un commit già durevole, EOF non deve cancellare il gruppo. Blocco locale e
  uscita sono azioni distinte da serializzare e persistere: non rollback retroattivi
  di una firma o revoche globali della credenziale già consegnata.
- L'appartenenza non autorizza da sola traffico/sessioni o cronologia pregressa.
  Trust PoC, identità e formato wire 0 restano invariati.

## Opzione A — commit locale atomico, nuovo confronto se interrotto prima

**Scelta dall'utente**, usa le conferme esistenti senza nuovi messaggi distribuiti.
Il punto irreversibile è il commit SQLite del nuovo
membro, arbitrato dal suo owner ancora vivo. Non è un commit simultaneo sui due device
e non dimostra all'emittente che il salvataggio sia riuscito.

L'emittente autorizza con la credenziale firmata e il confronto previsto; non mantiene
un secondo elenco globale di appartenenza che debba committare insieme al destinatario.
La successiva autenticazione di gruppo richiederà la prova durevole verificata, non un
pin promosso dal journal. UI/servizio non devono mostrare «salvato sul peer» dalla sola
conferma o dalla write: tale esito non è attestato dall'attuale wire.

| Interruzione osservata | Risultato richiesto |
|---|---|
| Prima delle due conferme | Nessun commit; tentativo chiuso |
| Dopo conferme/stage, prima del commit locale | Nessun ingresso dal journal; occorrono nuova selezione TLS, nonce e confronto esplicito |
| Durante la transazione | Tutto o niente al riavvio; appartenenza completa oppure solo materiale pendente non autorizzante |
| Commit riuscito, processo morto prima della notifica UI | Appartenenza durevole riletta e verificata con l'identità OS; nessun secondo ingresso |
| EOF dopo il commit locale | Gruppo conservato; nessuna promessa di stato equivalente o notifica già ricevuta dall'emittente |
| Journal ignoto/corrotto, identità cambiata o record in conflitto | Errore distinto, nessuna promozione/rimozione/sostituzione automatica |

Un nuovo confronto non riusa il consenso, la deadline o l'ID tentativo precedenti.
La sostituzione di materiale pendente richiede un'azione esplicita del percorso di
riprova e rimozione condizionale del record esatto; non è cleanup automatico all'avvio.
Il recupero automatico riguarda solo un commit locale già durevole, non un consenso
interrotto. Questa scelta è stata confermata esplicitamente dall'utente.

## Alternativa B non adottata — ripresa coordinata senza nuovo confronto

Se è richiesto completare automaticamente un'ammissione interrotta prima del commit,
non basta A e non basta aggiungere un ACK. Occorrono decisioni durevoli e autenticabili,
identificazione condivisa dell'operazione e binding al contesto, regole di interrogazione
e retry su nuovo TLS, conflitti, uscita/blocco e gestione dello stato «esito sconosciuto».
Durante una partizione non si può promettere sia esito immediato sia conoscenza concorde
dell'esito remoto. Un ACK perso non equivale a rollback.

Questa opzione richiede una specifica distribuita separata e una decisione esplicita
su estensione/negoziazione wire e migrazione dello stato di entrambi i partecipanti.
Non si assegna retroattivamente a `GROUP_CONFIRM` o al journal il significato di commit.
Nessun nome/codice di nuovi frame o protocollo di recovery viene fissato qui.

## Implementazione della politica A

`GroupAdoptionRepository` separa il deposito pendente dal marker durevole. La nuova
tabella `group_adoption` conserva l'intero record, compreso il payload journal v1 già
esistente, quindi proof, certificati e firme; nessun nuovo codec. `commitGroupAdoption`
fa INSERT condizionale dal journal esatto, ricontrolla il risultato e rimuove soltanto
quel journal nella medesima transazione. Retry esatto già committato restituisce false;
conflitti/identità cambiata/stage assente falliscono senza sostituzioni. Non è un'API
di verifica del consenso: è consumata dal core/owner fidato, non esposta a Swift per
scritture arbitrarie. Le letture del marker verificano metadati/BLOB, non le firme.

`localGroup()` legge la radice fondata O adottata, rifiutando dati durevoli malformati
e la presenza contemporanea di due origini. `foundLocalGroup` resta solo fondazione:
il suo INSERT e lo stage ora escludono anche l'adozione. Questo mantiene un solo gruppo
fra connessioni SQLite indipendenti. I consumer di preparazione vedono così anche
un'appartenenza adottata; la presentazione di un membro non fondatore spetta a B3.

`GroupRootAdoptionHandover.commitLocal` è l'orchestrazione Kotlin comune, consumata
direttamente da GroupRootAdoptionConnection e dalla facciata/owner Apple. Solo il vivo
Confirmed può iniziare; identità OS fornita dal caller serializzato, stage e nuovo
controllo di liveness/deadline prima di entrare nel commit sincrono. Nessun timer viene
resettato. Il caller mantiene il lock/executor lifecycle per tutta l'operazione non-UI:
eventi accodati durante la transazione sono ordinati dopo il suo esito. La deadline
abilita l'ingresso, non interrompe SQLite in corso; non si eseguono clock/OS/network/UI
callback dentro la transazione e non si annulla retroattivamente un commit riuscito.

L'opzione `replacingInterrupted`, fornita soltanto per una riprova esplicita DOPO un
nuovo confronto completo, rimuove condizionalmente il vecchio record intero. Richiede
la stessa identità locale e un ID tentativo differente. Un mismatch non elimina nulla;
la firma storica non sostituisce il consenso fresco. Un crash dopo la rimozione ma prima
del nuovo stage lascia nessuna appartenenza e richiede ancora un nuovo confronto.
Non si ripulisce all'avvio né si sovrascrive un pendente diverso automaticamente.

Su successo lo stato è Committed e il trasporto viene ritirato senza cancellare il
gruppo. Swift pubblica lo snapshot COMMITTED, non un falso errore onClosed; cancella
receive/timer e conserva il contratto whenClosedAndDrained prima di chiudere SQLite.
JVM richiede join degli I/O prima del commit e chiude la socket come già previsto.
Ticket e consenso transitori non diventano autorizzazione al traffico applicativo.

Errore prima dell'ingresso nel commit: tentativo chiuso, causa originale e prima revoca
preservate. Errore dalla chiamata di commit: CommitOutcomeUnknown terminale, mai replay
automatico. Il risultato va riletto tramite committedGroupAdoption (anche in IosPersistence)
e verificato con identità OS corrente e ispettore storico esistente. L'assenza del marker
non autorizza la promozione del solo pendente; marker già durevole e valido non richiede
nuovi clic. Questa rilettura è disponibile/testata, non ancora orchestrata nella UI.

## Accettazione e limiti

Un solo blocco B2, non una sequenza di facciate prive di consumer:

1. Contratto comune di appartenenza/risultato durevole e transazione SQLDelight con
   migrazione preservativa, idempotenza esatta e arbitraggio contro la fondazione.
2. Orchestrazione Kotlin consumata dagli owner JVM/Android e dalla facciata/owner
   Apple: stessa ownership, lifecycle, identità OS e timer; commit/stato osservabili.
   Nessun protocollo duplicato in Swift o callback OS sotto transazione.
3. Test delle regole comuni; integrazioni TLS/firme/SQLite per i punti della matrice,
   concorrenza, rollback, commit riuscito con notifica persa, conflitti e riapertura.
   Apple Native/simulatore al checkpoint integrato, non dopo ogni classe.

Regressioni mantenute: regole/revoche/reentrancy/esito ambiguo comuni; JDBC per commit,
retry/conflitti, rollback dopo INSERT/DELETE, read-only/corruzione, migrazioni 1/2/3→4 e
gara fondazione/adozione; TLS/P-256/SQLite con riapertura, nuovo confronto e riprova,
errore prima/dopo commit reale senza notifica, nessun trust PoC/storia creato.
Tre nuovi test Native e cinque XCTest (tre facciata, due owner TLS/drain) predisposti.
Windows non verifica export/Swift o simulatore: esito del checkpoint nuovo in STATO.

Non attivare servizio/UI (B3), sessioni o traffico prima dell'accettazione B2.
Hardware di fase 1 ancora obbligatorio. Il commit locale non è commit distribuito,
né l'ammissione già utilizzabile nell'app: ingresso servizio e UI restano separati.
