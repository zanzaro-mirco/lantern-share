# ADR 021 — ripresa nella stessa sessione dopo una consegna interrotta

Data: 26 ottobre 2026. Blocco successivo a B10 e alla stabilità dei Node. Evolve una regola di [ADR 014](ADR-014-NEGOZIAZIONE-INIZIALE-SESSIONE.md).

## Problema

L'autore segna la sessione `used` prima del salvataggio durevole e dell'invio della busta ([ADR 015](ADR-015-TESTO-GRUPPO-DUREVOLE.md)–[016](ADR-016-PRIMO-TRASFERIMENTO-TESTO-GRUPPO.md)); il ricevente lo fa solo all'ingresso del proprio commit. Se la consegna si interrompe fra i due punti (salvataggio dell'autore fallito, trasporto chiuso, verifica o timeout prima del commit del ricevente) ed entrambi i servizi restano attivi, le due offerte successive descrivono **la stessa sessione** con `used` diverso. `SessionSelector` le rifiutava come «osservazioni contraddittorie»: ogni nuovo tentativo fra quei due dispositivi falliva finché la run non veniva azzerata, perdendo la sessione anche per gli altri partecipanti.

## Decisione

Per lo stesso gruppo e lo stesso ID di sessione, le osservazioni che differiscono solo per `used` convergono a **`used = true`**, in qualsiasi ordine. `used` è monotono per definizione (ADR 014/015): l'unione è il massimo del reticolo, non una scelta per ordine di arrivo né un declassamento. Il gruppo è già filtrato e l'ID è la chiave, quindi `used` è l'unico campo che può differire.

Invariato tutto il resto:

- sessioni con ID diversi: minimo deterministico fra le vuote, precedenza dell'unica usata, scelta esplicita fra più usate;
- le proposte nuove non possono essere usate e restano solo fallback quando nessuno mantiene una sessione;
- le offerte si leggono solo dopo la verifica di appartenenza sul TLS vivo; formato LSN 133 byte, HELLO, LTC/LGA, schema 5 e identità invariati;
- per una sessione usata restano le guardie esistenti: senza snapshot del roster conservato il testo legacy e il roster sono rifiutati (`ROSTER_REQUIRED`, partecipanti mancanti), mai ricostruiti;
- i contatori riservati dal tentativo interrotto non sono riusati; il nuovo tentativo è una consegna esplicita, non una ritrasmissione automatica.

## Sicurezza

Un membro autenticato può dichiarare `used` per la sessione mantenuta dall'altro. L'effetto è solo conservativo (la sessione diventa usata localmente e richiede le guardie del roster), lo stesso che otterrebbe inviando davvero un testo: nessuna nuova autorità, sessione, destinatario o trust PoC. Nessun declassamento da `used` a vuota è possibile.

## Accettazione e verifica

- Test comuni: osservazioni discordanti della stessa sessione convergono come usate in entrambi gli ordini; le regole fra sessioni diverse restano.
- JVM reale (Node, TLS, P-256, SQLite): salvataggio dell'autore fallito dopo `used`, nessuna busta al ricevente; il nuovo tentativo nella stessa run usa la stessa sessione, contatore successivo 2, ricevute esatte, negoziazione diagnostica concorde su `used`; percorso con roster e legacy.
- iOS: stesso selettore comune; XCTest della facciata con la coppia copia installata dopo la firma dell'autore. Native/XCTest solo con un checkpoint Apple completo.

## Confini

Non introduce ritrasmissione automatica, connessione persistente, reconnect, scelta operativa fra più sessioni usate, propagazione delle ricevute o ripristino della sessione dopo uno `stop`. Hardware non attestato.
