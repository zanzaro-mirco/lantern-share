# ADR 019 — copia originale dell'autore dopo nuovi ingressi

Data: 25 ottobre 2026. Seguito di [ADR 018](ADR-018-CONSEGNA-TESTO-CON-ROSTER.md); stessi ingressi Node/UI Android/desktop e Bonjour/iOS.

> Evoluzione: l'inoltro della stessa busta da un destinatario non autore è una modalità distinta, [ADR 020](ADR-020-COPIA-INOLTRATA-DA-DESTINATARIO.md). Le regole sotto restano quelle della copia dell'autore.

## Risultato e accettazione

**Consegna copia** dell'autore funziona anche quando, dopo la firma, nella stessa
sessione sono entrati altri membri. A e B scambiano un testo; C entra; l'autore
può riconsegnare la stessa busta (UUID, contatori, corpo, destinatari, firma) a un
destinatario originale, anche se questo non l'aveva mai ricevuta ed era offline.
C viene rifiutato prima del pin perché non appartiene allo snapshot congelato.
Duplicati e riaperture non riservano contatori; il prossimo nuovo testo usa il
contatore successivo e tutti i partecipanti correnti. Ricevute per destinatario
invariate. Stop di tutti produce una nuova sessione: la copia viene rifiutata
come ROSTER_REQUIRED, senza riattivare la sessione archiviata.

Non è sufficiente togliere l'uguaglianza del roster: la modalità copia è una
continuazione negoziata e legata all'accordo esatto dello scope.

## Negoziazione e wire additivi

- Nuova feature `group-roster-text-copy`. L'autore di una copia salvata la
  dichiara **supportata e richiesta**; ogni ricevente ROSTER_TEXT la supporta e
  non la richiede mai; un nuovo testo non la dichiara. Combinazioni diverse sono
  rifiutate (`GroupRosterTextCodec.savedCopy`). Un ricevente precedente senza la
  feature fallisce già nella negoziazione HELLO, prima delle prove.
- La modalità deriva soltanto dagli HELLO autenticati, mai dalla busta o dall'ID
  scelto in UI. Swift la riceve dall'owner (`selectRoster` con terzo argomento) e
  `checkBinding` la ricontrolla contro gli offerte.
- **LTC versione 2**, stessi 324 byte e campi della versione 1 (gruppo, sessione,
  autore, destinatario TLS, SHA-256 del roster LRO concordato). Entrambi i lati la
  costruiscono indipendentemente e confrontano tutti i byte: un disaccordo sulla
  modalità chiude la connessione. Busta `GROUP_TEXT`, LGA 360 byte, LTX/LTA,
  schema 5/4.sqm e versioni restano invariati.

## Regole della copia

`GroupRosterTextContext(savedCopy = true)` mantiene `recipients` uguale al roster
vivo per i controlli di run/memoria (`markUsed`, `checkCurrent`) e verifica la
busta così: stesso gruppo e sessione, autore uguale al certificato TLS mittente,
destinatario TLS dentro lo snapshot firmato, snapshot interamente contenuto nel
roster corrente verificato con prove nuove. `expectedRecipients` passa all'inbox
lo snapshot firmato solo dopo questi controlli. Un nuovo testo usa ancora
l'uguaglianza con l'intero roster; una copia non può firmare né riservare
contatori, un nuovo testo non può viaggiare nello scope copia.

Mittente: preflight invariato prima del pin (autore locale, gruppo, peer fra i
destinatari). Dopo LRA verifica firma OS della copia, sessione/snapshot e
salva in modo idempotente; incoerenza con la sessione viva → ROSTER_REQUIRED.
Ricevente: stessa sequenza HELLO → LGM → LSN → LRO → LRA → LTC → testo → LGA,
stesso owner, reader e timer originale; firma OS prima della scrittura, Used
conservativo, ACK dopo commit.

## Limite dichiarato

Le attestazioni B7 non portano un ordine temporale. Il ricevente verifica che lo
snapshot sia firmato dall'autore e contenuto nel roster corrente, ma non può
dimostrare che la firma preceda gli ingressi successivi. La garanzia "nessun
sottoinsieme firmato dopo l'ingresso" resta quindi del client autore onesto,
che non rifirma copie e firma i nuovi testi sull'intero roster. Una prova
crittografica dell'ordine richiederebbe un nuovo formato firmato: decisione
separata, non presa qui.

## Confini

Core Kotlin per negoziazione, scope, contesto e ACK; Node e owner JVM per
capacità e continuazione; facciate iOS Kotlin e owner Swift come in ADR 018.
Esclusi: inoltro da altri destinatari (poi ADR 020), distribuzione automatica, connessione
persistente, paginazione, scelta fra sessioni usate e UI completa. Evidenze e
limiti di verifica in [STATO](../STATO_SVILUPPO.md); fase 1/hardware e gate UI
invariati.
