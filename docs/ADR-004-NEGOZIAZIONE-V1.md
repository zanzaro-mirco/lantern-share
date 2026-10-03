# ADR 004 — fondamenta della negoziazione v1

## Ambito e stato

Il 3 ottobre 2026 l'utente ha rinviato i collaudi fisici e chiesto di proseguire. Restano obbligatori in fase 1; il rinvio non ne certifica l'esito. Si avvia soltanto la regola pura di negoziazione v1 nel modulo Kotlin `protocol`, non un nuovo trasporto o l'intero protocollo di prodotto.

## Decisione

`ProtocolCapabilities` descrive una singola versione con funzionalità supportate e richieste. Ogni requisito deve essere anche supportato dal proponente. Nomi ASCII minuscoli (`[a-z][a-z0-9-]{0,31}`), massimo 32 funzionalità e versioni 1–255 limitano l'input del futuro codec. Questi sono limiti del nuovo contratto, non modifiche al v0. Le collezioni in ingresso vengono copiate.

`ProtocolNegotiation` accetta solo versione 1 su entrambi i lati, calcola l'intersezione delle funzionalità e rifiuta se manca un requisito di uno qualsiasi dei due peer. Funzionalità opzionali sconosciute sono ignorate tramite l'intersezione; quelle obbligatorie non possono essere ignorate. Il risultato è simmetrico, con funzionalità ordinate deterministicamente. L'insieme vuoto è consentito a questo livello: sarà il servizio a richiedere le capacità necessarie al proprio flusso. Nessun insieme predefinito dichiara funzionalità di prodotto già disponibili.

La negoziazione non concede autorizzazioni. Il futuro handshake dovrà autenticare e vincolare le offerte al transcript della connessione prima di abilitarne il risultato. Non è consentito ripiegare automaticamente al v0 dopo un rifiuto v1.

## Compatibilità e limiti

Nessun chiamante di produzione usa ancora questa regola. `Wire`, framing, firme, annunci Bonjour v0, identità e schema SQLite rimangono invariati. Nessun nuovo frame viene inviato; nessun dato viene migrato. Il modello non è ancora un formato serializzato: codec, envelope, transcript autenticato e attivazione/versionamento nel trasporto richiedono incrementi separati ed espliciti. Non si dichiara completo il protocollo v1 né l'interoperabilità v0/v1.

## Verifica e prossimo incremento

Test comuni: intersezione e ordine, simmetria, requisiti mancanti sui due lati, funzionalità opzionali future, versioni non implementate anche uguali, limiti/input invalidi e copia delle collezioni. La suite v0 rimane attiva per proteggere il contratto esistente.

Prossimo incremento concreto: codec Kotlin rigoroso delle offerte v1, con vettori JSON positivi/negativi e dimensioni limitate, ancora separato dal canale v0. Non attivare la negoziazione non autenticata in rete.
