# ADR 024 — copia esplicita fra sessioni diverse

Data: 5 novembre 2026. Blocco approvato dall’utente, successivo al consolidamento dell’uscita locale. Estende il limite dei destinatari congelati di [ADR 022](ADR-022-SCELTA-ESPLICITA-FRA-SESSIONI-USATE.md).

## Risultato e decisione

Un destinatario originale che mantiene un’altra sessione può ricevere una copia esplicita senza abbandonare la propria. Il mittente è l’autore oppure un altro destinatario originale ([ADR 019](ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md)–[020](ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md)) e deve conservare il roster firmato della sessione della copia.

- La modalità copia proviene dai requisiti HELLO già negoziati, mai dalla busta. Quando entrambi mantengono sessioni diverse, la regola comune `GroupRosterTextCodec.selectSession` usa per questa consegna la sessione usata offerta dal mittente. Nuovi testi e negoziazioni ordinarie mantengono le regole e la scelta esplicita di ADR 022.
- Appartenenza sul TLS vivo, join firmate, unione completa del roster e accordo LRA restano obbligatori. Il mittente senza roster conservato rifiuta questo percorso. Il recupero precedente dopo il riavvio dell’autore resta possibile quando il ricevente conserva la sessione/il roster: non si ricostruisce alcuno snapshot dalla cronologia.
- Il ricevente con un’altra sessione mantenuta verifica un roster limitato alla consegna. Non lo installa come sessione corrente, non ne fonde i partecipanti nella propria e non cambia il suo flag `used`. Il contesto scade con cancellazione, stop, cambio di appartenenza o della sessione mantenuta. JVM controlla l’esatta istanza conservata; Apple la revisione della memoria e il marker locale, sulla coda seriale esistente.
- La busta deve ancora corrispondere al gruppo e alla sessione verificati. Firma, destinatari congelati, contatore dell’autore e tempo logico restano identici. Il destinatario TLS deve essere fra quelli originali; per un inoltro anche il mittente deve esserlo e la firma si verifica con la join dell’autore. Estranei, membri successivi e inoltri verso l’autore restano rifiutati. L’ACK segue il salvataggio SQLite e riguarda soltanto il dispositivo raggiunto.

## Compatibilità e confini

Nessuna nuova feature, versione o struttura wire: HELLO/LGM/LSN/LRO/LRA/LTC/LGA e busta invariati. Un peer precedente che mantiene un’altra sessione può ancora rifiutare la consegna; nessun fallback o allentamento dei controlli. SQLite 5, ultima migrazione 4.sqm, identità, autorizzazioni, contatori e ricevute esistenti sono preservati.

Non introduce una seconda sessione attiva, recupero automatico, ricostruzione dopo perdita di tutti gli snapshot, scelta automatica fra sessioni, cronologia UI, riconnessione o modifiche alle autorizzazioni. Resta il limite di ADR 019 sull’ordine temporale della firma non dimostrabile dal ricevente.

## Accettazione e verifica

- Regole comuni: una copia seleziona la sessione usata del mittente solo nel caso previsto; nuovi testi richiedono ancora la scelta; gruppi diversi e sessione vuota del mittente sono rifiutati. Recupero preesistente dopo riavvio conservato.
- Regressione mantenuta JVM con tre Node, TLS/P-256/SQLite reali, sia autore sia inoltratore: A non ha mai ricevuto il testo originale destinato anche a lui; mantiene una nuova sessione usata con C; riceve da B la stessa busta due volte, poi invia ancora nella sessione corrente con gli stessi partecipanti e contatore successivo. Anche B conserva la propria sessione e non consuma contatori per le copie. Un guasto SQLite in ricezione causa rollback senza ACK e lascia utilizzabile la sessione corrente. La storia senza il roster necessario non basta. Le regressioni esistenti continuano a controllare destinatari successivi/estranei, firme, ricevute, arresto e cancellazione.
- Due XCTest mantenuti: stesso scenario attraverso l’owner Swift, per autore/inoltratore; facciata Native con firma errata, memoria preservata e contesto rifiutato dopo reset. Scritti su Windows: compilazione Apple ed esecuzione su simulatore non attestate da questo blocco.

Comandi e risultati effettivi in [STATO](../STATO_SVILUPPO.md). Nessuna nuova prova hardware, run Apple o lettura CI.
