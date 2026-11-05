# ADR 022 — scelta esplicita fra sessioni usate

Data: 1 novembre 2026. Blocco B12, successivo al backoff dei Node. Completa il caso `Choose` di [ADR 014](ADR-014-NEGOZIAZIONE-INIZIALE-SESSIONE.md).

## Problema

Due dispositivi che mantengono sessioni **usate** diverse (ciascuno ha già scambiato testi con altri membri in questa run) ricevono `NeedsChoice`. Prima di questo blocco non esisteva alcun ingresso per decidere: il pannello mostrava solo «serve una scelta esplicita», e l'invio di testo o il roster fallivano con `SESSION_CHOICE_REQUIRED` senza via d'uscita se non lo stop del servizio.

## Decisione

La scelta è **locale ed esplicita** e non cambia il formato wire.

- `NeedsChoice` porta anche la sessione mantenuta da questo dispositivo (`held`), così l'utente distingue «la mia» dall'altra.
- `GroupSessionChoiceController.chooseGroupSession(choice, session)` agisce solo se `choice` è esattamente l'istanza pubblicata (identità `===`, come `confirmGroup`; i valori di un flusso possono ripetersi, ABA), se la sessione è fra quelle offerte e se la sessione mantenuta è ancora quella della lista. Una scelta stantia, estranea o già consumata è ignorata.
- Regola pura comune `SessionChoice.apply`: se la scelta è la sessione mantenuta, `Keep` (nulla cambia, partecipanti e roster restano); se è quella del peer, `Adopt`: la sessione mantenuta è **abbandonata** e sostituita dal candidato `used = true` con partecipanti e roster ignoti.
- La scelta **non** pubblica `Selected` e non fonde nulla: lo stato torna `Idle`. L'accordo nasce solo da una nuova negoziazione esplicita su entrambi. Se i due convergono sulla stessa sessione si ha `Join`; se ciascuno tiene la propria, o si scambiano, si ottiene di nuovo `NeedsChoice`.
- La scelta pendente è legata alla radice e al marker esatto di appartenenza e si azzera con annullamento, stop del servizio e ogni nuova selezione.

## Sicurezza

Adottare la sessione usata del peer non concede nulla di nuovo: lo stesso stato si raggiunge già con `Join(used.single())` quando un dispositivo con sessione vuota incontra uno con sessione usata. L'unica semantica nuova è l'abbandono della propria sessione usata.

- **Contatori:** il contatore dell'autore è nel database per gruppo e autore (`reserveGroupTextCounters`), non nella sessione in memoria: cambiare sessione non può riusarlo.
- **Ambito:** con partecipanti ignoti il testo legacy resta rifiutato (`ROSTER_REQUIRED`). Il testo con roster ricostruisce l'ambito firmato nello stesso scambio, perché lo snapshot conservato dell'altro dispositivo lo ripristina; senza snapshot conservato nessuno dei due, il roster è rifiutato (partecipanti mancanti).
- **Sessione abbandonata, limite originario di B12:** gli altri suoi membri continuano a elencare questo dispositivo come destinatario congelato. In B12 le loro copie salvate ([ADR 019](ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md)–[020](ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md)) non lo raggiungevano finché non sceglieva di nuovo quella sessione. Estensione approvata il 5 novembre: [ADR 024](ADR-024-COPIA-FRA-SESSIONI-DIVERSE.md), consegna esplicita con il roster conservato dal mittente senza sostituire la sessione corrente; verifiche e limiti Apple/hardware in STATO.

## Accettazione e verifica

- Comune: `SessionChoice.apply` mantiene o adotta come usata, rifiuta sessioni mai offerte, di altro gruppo o con sessione mantenuta fuori lista.
- JVM reale (tre membri, Node, TLS, P-256, SQLite): due sessioni usate diverse su A e B danno `NeedsChoice` su entrambi con `held` corretto; una scelta non offerta non cambia lo stato; entrambi tengono la propria, nulla si fonde e la negoziazione successiva richiede ancora la scelta; A adotta quella di B e B la tiene, una scelta già consumata è ignorata, la negoziazione successiva seleziona la stessa sessione; il testo legacy è rifiutato (`ROSTER_REQUIRED`), il testo con roster riesce nella sessione adottata con contatore successivo 2. Verificato per mutazione (adozione non installata; scelta non consumata).
- Pannello desktop: pulsanti «Tieni la tua» / «Passa a» solo per un controller che implementa il contratto.
- iOS, host JVM: il controller inoltra la scelta solo con handler impostato, per l'istanza pubblicata e per una sessione della lista; lo stato torna `Idle` solo se la memoria ha applicato la scelta e non per una risposta in ritardo (verificato per mutazione). XCTest `testExplicitChoiceKeepsOrAdoptsTheirsAsUsedAndRefusesStaleOrReset` con la memoria Kotlin Native vera: `Keep`, `Adopt` (la proposta successiva è la sessione del peer come usata), ripetizione idempotente, scelta rifiutata dopo `reset`. Scritto ma **non compilato né eseguito** finché non c'è un checkpoint Apple completo.

## Ingresso iOS

Stessa semantica, stesso pannello condiviso (`GroupSessionPanel` vive in `commonMain`). La memoria di sessione appartiene alla coda seriale del servizio nativo, quindi la scelta non la tocca dalla UI:

- `IosGroupAdmissionController` implementa `GroupSessionChoiceController` e inoltra la scelta a un `choiceHandler` impostato una volta dal servizio nativo. **Senza handler la scelta è ignorata**, mai applicata in silenzio. Il click è accettato solo per l'istanza `NeedsChoice` pubblicata e per una sessione della sua lista.
- `IosPairingService` accoda sulla propria coda `IosGroupSessionMemory.choose(request)` e risponde con `sessionChosen(request, applied)`: lo stato torna `Idle` solo se la memoria ha applicato la scelta e solo per quella stessa istanza (una risposta in ritardo non tocca una negoziazione nuova).
- `IosGroupSessionMemory.choose` usa la stessa regola pura `SessionChoice.apply`: `Keep` non cambia nulla, `Adopt` sostituisce la sessione mantenuta con quella del peer come usata, ambito ignoto, mantenendo radice e marker; false per gruppo diverso, memoria azzerata o scelta fuori lista. `IosGroupSessionResult` porta ora anche la sessione mantenuta, così `NeedsChoice.held` è valorizzato.
- Nessun cambio a wire, HELLO, schema, firme o costruttore pubblico del controller (le chiamate Swift esistenti restano valide).

## Confini

Non introduce fusione, scelta automatica, sincronizzazione della cronologia o ripristino dopo uno stop. Hardware non attestato.
