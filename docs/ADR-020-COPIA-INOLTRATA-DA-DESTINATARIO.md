# ADR 020 — copia inoltrata da un destinatario autorizzato

Data: 25 ottobre 2026. Seguito di [ADR 018](ADR-018-CONSEGNA-TESTO-CON-ROSTER.md) e [ADR 019](ADR-019-COPIA-ORIGINALE-DOPO-NUOVI-INGRESSI.md); stessi ingressi Node/UI Android/desktop e Bonjour/iOS.

## Risultato e accettazione

**Consegna copia** funziona anche quando a consegnare è un destinatario originale
che non è l'autore. B firma un testo per {A, B, C}; C lo riceve; A è offline.
Quando A rientra, C può consegnargli la **stessa busta** (UUID, contatori, corpo,
destinatari, firma di B) senza che B sia presente. A salva i byte invariati
verificando la firma con il certificato di B preso dal roster vivo appena
verificato, non dal certificato TLS di C.

Sono rifiutati prima del pin, con la stessa azione: la consegna all'autore, a un
membro entrato dopo la firma, a un non destinatario e la consegna di un testo che
il dispositivo locale non ha salvato come destinatario. Duplicati e copie già
ricevute restano idempotenti; nessun contatore viene riservato né rifirmato.
Stop di tutti produce una nuova sessione: la copia inoltrata viene rifiutata come
ROSTER_REQUIRED, senza riattivare la sessione archiviata.

## Prova distinta dalla consegna dell'autore

- Nuova feature `group-roster-text-relay`. Chi inoltra la dichiara **supportata e
  richiesta**; ogni ricevente ROSTER_TEXT la supporta e non la richiede mai.
  L'autore di una copia usa invece `group-roster-text-copy` (ADR 019): le due
  richieste sono mutuamente esclusive e un nuovo testo non dichiara nessuna delle
  due (`GroupRosterTextCodec.relayedCopy`). Un ricevente precedente fallisce già
  negli HELLO, prima delle prove.
- La modalità deriva solo dagli HELLO autenticati. Il mittente la sceglie
  localmente dalla copia salvata (autore locale → copia dell'autore, altrimenti
  inoltro); il ricevente non la deduce mai dalla busta. Swift la riceve
  dall'owner (`selectRoster` con quarto argomento) e `checkBinding` la ricontrolla.
- **LTC versione 3**, stessi 324 byte e campi (gruppo, sessione, mittente TLS,
  destinatario TLS, SHA-256 del roster LRO concordato). L'ACK LGA a 360 byte lega
  il mittente TLS che ha inoltrato. Busta `GROUP_TEXT`, LTX/LTA, schema 5/4.sqm e
  versioni invariati.

## Regole dell'inoltro

`GroupRosterTextContext(relayedCopy = true)` accetta solo una busta con stesso
gruppo e sessione, autore diverso da mittente e destinatario TLS, entrambi
compresi nello snapshot firmato, e snapshot interamente contenuto nel roster
corrente verificato con prove nuove. `authorCertificate` restituisce il
certificato della join dell'autore in quel roster: la firma della busta si
verifica con il verificatore OS dei certificati di gruppo (DER, pin, tempo),
come per le join. `GroupTextReceiver` accetta il mittente TLS diverso dall'autore
solo in questa modalità.

Mittente: preflight prima del pin (gruppo, copia salvata con ricevuta locale,
locale e peer fra i destinatari, peer diverso dall'autore). Dopo LRA verifica
firma, sessione e snapshot; incoerenza con la sessione viva → ROSTER_REQUIRED.
La ricevuta del destinatario si registra nell'archivio di chi inoltra come prova
locale della propria consegna: l'autore non la riceve e le sue ricevute non
cambiano. Ricevente: stessa sequenza HELLO → LGM → LSN → LRO → LRA → LTC → testo
→ LGA, stesso owner, reader e timer originale; firma OS prima della scrittura,
Used conservativo, ACK dopo commit.

## Limiti dichiarati

Resta il limite di ADR 019: il ricevente non può dimostrare che lo snapshot
firmato preceda gli ingressi successivi. L'autore deve essere presente nel
roster vivo con una join firmata (anche conservata da un altro partecipante);
se nessuno conserva la sua join nella sessione, l'inoltro non è possibile.
Il ricevente non distingue un inoltro da una consegna diretta nell'interfaccia,
oltre al mittente indicato nello stato.

## Confini

Core Kotlin per negoziazione, scope, contesto, certificato dell'autore e
ricezione; Node e owner JVM per capacità, preflight e verifica; facciate iOS
Kotlin e owner/sessione Swift come in ADR 018–019. Esclusi: distribuzione
automatica o a catena, sincronizzazione della cronologia, propagazione delle
ricevute all'autore, connessione persistente, paginazione, scelta fra sessioni
usate e UI completa. Evidenze e limiti di verifica in [STATO](../STATO_SVILUPPO.md);
fase 1/hardware e gate UI invariati.
