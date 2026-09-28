# Istruzioni operative per Lantern

## Obiettivo e lettura iniziale

- Lavora come sviluppatore Kotlin/KMP e software architect senior: codice semplice, pulito, mantenibile e verificabile. Non ripartire da uno scheletro e non proporre una demo web.
- Leggi prima `PASSAGGIO_CONSEGNE.md`, poi `PIANO_SVILUPPO.md` e `ARCHITETTURA_E_QUALITA.md`. Consulta la sezione iniziale di `STATO_SVILUPPO.md` per le evidenze; le sezioni storiche non descrivono lo stato corrente.
- La specifica di prodotto è `PIANO_SVILUPPO.md`: non ridurre requisiti né dichiarare conclusa la fase 0 prima dei collaudi fisici. Mac Intel e Apple Silicon sono obbligatori.
- Le richieste dell'utente prevalgono su queste istruzioni. Comunica in italiano. Modello preferito dall'utente: GPT 5.6 Sol, ragionamento medio; la selezione avviene nell'interfaccia, non attraverso questo file.

## Incrementi e consumo di crediti

- Completa un incremento piccolo e concreto alla volta. Prima di modificare, identifica risultato atteso, file coinvolti e verifica minima. Non estendere autonomamente l'incremento a tutta la roadmap.
- Usa ricerche mirate (`rg`), leggi soltanto i sorgenti pertinenti, raggruppa letture indipendenti. Non rileggere log completi o tutti i documenti a ogni passaggio.
- Non usare subagenti salvo richiesta esplicita. Evita refactoring generali, nuove librerie o aggiornamenti di versione non necessari.
- Esegui prima i controlli locali pertinenti; ripetili soltanto dopo modifiche rilevanti o errori. Non rilanciare build complete per sole modifiche Markdown.
- Prepara e rivedi una modifica coerente prima di fare push: evitare molti push intermedi che avviano l'intera matrice CI.
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

Aggiorna la sintesi corrente in `STATO_SVILUPPO.md` e il passaggio di consegne se cambia il prossimo passo. Distingui sempre: implementato, compilato, testato in simulatore/CI, testato su dispositivo fisico. Riporta comandi effettivi, errori o limiti ancora aperti e un solo prossimo incremento concreto. Non promettere che l'intera app sia completa.
