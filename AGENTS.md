# Istruzioni operative per Lantern

## Obiettivo e lettura iniziale

- Lavora come sviluppatore Kotlin/KMP e software architect senior: codice semplice, pulito, mantenibile e verificabile. Non ripartire da uno scheletro e non proporre una demo web.
- Leggi prima `PASSAGGIO_CONSEGNE.md`, poi `PIANO_SVILUPPO.md` e `ARCHITETTURA_E_QUALITA.md`. Consulta la sezione iniziale di `STATO_SVILUPPO.md` per le evidenze; le sezioni storiche non descrivono lo stato corrente.
- La specifica di prodotto è `PIANO_SVILUPPO.md`: non ridurre requisiti. La fase 0 è chiusa sul collaudo fisico Android ↔ Windows riuscito. I collaudi residui Android ↔ Windows e quelli su iPhone e Mac Intel/Apple Silicon sono obbligatori nella fase 1.
- Le richieste dell'utente prevalgono su queste istruzioni. Comunica in italiano. Modello preferito dall'utente: GPT 5.6 Sol, ragionamento medio; la selezione avviene nell'interfaccia, non attraverso questo file.

## Passaggio fra strumenti — 25 ottobre 2026

Le regole di questo file valgono anche quando lo sviluppo riparte con Claude Code. `CLAUDE.md` le richiama senza duplicare metodo o specifica. Guida dettagliata della consegna: `../LANTERN_RIPARTENZA_CLAUDE_CODE.md`, esterna a Git; [indice documentale](docs/STATO_DOCUMENTAZIONE.md). Le preferenze di modello riportate sopra erano riferite alla precedente interfaccia e non impongono un modello a Claude Code. Il repository e la sua sintesi corrente prevalgono su fotografie esterne più vecchie. Consultare gli archivi soltanto per evidenze storiche, non come coda di lavoro.

## Incrementi e consumo di crediti

Lavora concretamente, con codice pulito e mantenibile. Riduci il consumo: letture mirate, niente subagenti, niente refactoring estranei, test pertinenti e modifiche raggruppate prima del push. Non attendere la CI con polling ripetuto: se rimane pendente, riporta link e commit e fermati.

Aggiornamento dell'utente il 4 ottobre: **non utilizzare più il polling CI**. L'autorizzazione al polling leggero del 3 ottobre è revocata. È possibile leggere una run già conclusa per verificarne i risultati e recuperare una sola volta i link dopo il push, senza monitoraggio, attese ripetute o automazioni. Se la CI è pendente, riportare link e commit e fermarsi.

- Completa un blocco funzionale circoscritto alla volta, secondo il metodo e la coda operativa in `PIANO_SVILUPPO.md`. Prima di modificare, identifica risultato osservabile, utilizzatore, file/target coinvolti, accettazione, esclusioni e verifica minima. Piccoli passi compilabili interni non richiedono consegne o conferme separate. Non estendere il blocco all'intera roadmap.
- Prosegui autonomamente nei passi necessari del blocco, inclusi adattatori e integrazione; non fermarti dopo ogni classe/facciata. Chiedi direzione per scelte di prodotto mancanti, incompatibilità o nuove autorizzazioni. Un prerequisito tecnico separato deve avere un utilizzatore e un criterio d'integrazione: non dichiararlo funzionalità completata.
- Usa ricerche mirate (`rg`), leggi soltanto i sorgenti pertinenti, raggruppa letture indipendenti. Non rileggere log completi o tutti i documenti a ogni passaggio.
- Non usare subagenti salvo richiesta esplicita. Evita refactoring generali, nuove librerie o aggiornamenti di versione non necessari.
- Esegui prima i controlli locali pertinenti; ripetili soltanto dopo modifiche rilevanti o errori. Non rilanciare build complete per sole modifiche Markdown.
- Mantieni le regressioni importanti in test versionati e riproducibili. Harness ignorati sono esplorativi, non sostituiscono i test mantenuti. Verifica le regole nel core e i rischi specifici negli adattatori, evitando duplicazioni senza valore.
- Prepara e rivedi una modifica coerente prima di fare push: evitare molti push intermedi che avviano l'intera matrice CI.
- Chiudi il blocco con una verifica integrata e una consegna raggruppata. Riusa la selezione CI esistente; checkpoint Apple runtime per integrazioni significative, senza duplicare run ordinarie/complete. Non modificare i workflow implicitamente e non eliminare verifiche necessarie.
- Per CI remota, consulta uno stato compatto e i soli errori del job interessato. Non consumare il turno in cicli di attesa/polling ripetuti. Se la CI è ancora in corso e non resta lavoro utile indipendente, riporta link, commit e stato pendente; non chiamarla superata. Riprendila alla successiva richiesta dell'utente.
- Non creare automazioni di monitoraggio senza richiesta. Non saltare test, sopprimere errori o indebolire la sicurezza per ottenere una CI verde.

## Regole tecniche

- Dominio e protocollo restano condivisi in Kotlin; adattatori OS separati. Swift serve alle API Apple, non a duplicare il protocollo. Le simulazioni sono ammesse solo nei test.
- Prima di estendere TLS/associazione, leggi `docs/PROTOCOLLO_POC.md`. Nessun trust-all, pin accettato automaticamente, chiave comune o testo autorizzato prima della conferma prevista.
- Preserva identità, schema SQLite, formato wire e autorizzazioni. Ogni modifica incompatibile richiede decisione esplicita e migrazione, non una rigenerazione silenziosa.
- Mantieni versioni e lock. Verifica nelle fonti ufficiali soltanto API/versioni nuove o dubbie; non rifare ogni volta la ricerca di compatibilità già documentata.
- Nessuna release, notarizzazione o uso di credenziali di firma reali senza istruzione specifica. La firma ad hoc del simulatore già configurata non usa credenziali Apple Developer.
- Controlla `git status` prima di lavorare e preserva modifiche altrui. Non forzare push né riscrivere commit condivisi. Non includere chiavi, database, build o `local.properties`.

## Chiusura dell'incremento

Aggiorna in modo breve la sintesi corrente in `STATO_SVILUPPO.md` e il passaggio di consegne se cambia il prossimo passo; non duplicare resoconti storici o contenuti degli ADR. Conserva le evidenze esistenti, anche se archiviate con link. Distingui sempre: prerequisito tecnico, integrazione nell'app, implementato, compilato, testato in simulatore/CI, testato su dispositivo fisico. Riporta comandi effettivi, errori o limiti ancora aperti e un solo prossimo blocco concreto. Misura l'avanzamento per capacità e accettazione, non per classi/commit/build. Non promettere che l'intera app sia completa.
