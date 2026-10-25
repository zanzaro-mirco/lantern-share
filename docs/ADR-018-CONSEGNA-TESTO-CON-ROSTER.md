# ADR 018 — consegna esplicita di testo con roster completo

Data: 25 ottobre 2026. Seguito di ADR 016–017, ingresso Node/UI Android/desktop.

## Risultato e accettazione

Un membro sceglie **Nuovo testo** verso un altro partecipante, che sceglie
**Ricevi**. Il TLS selezionato verifica nuovamente membership, sessione e roster
completo, incluse le attestazioni degli offline. Il testo firmato congela tutti
questi destinatari. Ogni tentativo consegna a un solo dispositivo, entro i 120 s
originali; la ricevuta segue il suo commit SQLite e vale soltanto per quel peer.
La UI distingue copie salvate e ricevute mancanti, senza dedurre presenza o
consegna agli altri da un singolo ACK.

**Consegna copia** usa l'ID di una copia locale già firmata dal mittente, anche
dopo riapertura SQLite se un peer mantiene ancora la sessione. Ripete tutte le
verifiche sul nuovo TLS e trasmette identici UUID, contatori, corpo, destinatari e
firma; non riserva nuovi contatori. Duplicati esatti sono idempotenti. Una copia
ricevuta da un altro autore non può essere inoltrata attraverso questo percorso.
L'ID immesso nella UI non è un'autorizzazione, né lo è la cronologia.

Questo ingresso richiede che lo snapshot congelato coincida con i partecipanti
del roster corrente verificato. Se nel frattempo sono entrati altri membri,
rifiuta la vecchia copia anziché rifirmarla, aggiungere destinatari retroattivi
o omettere partecipanti. Il futuro recupero dovrà gestire separatamente prove e
snapshot storici. Stop di tutti produce un nuovo ID sessione e non permette di
riattivare quella archiviata tramite un messaggio salvato.

Accettazione: tre membri, fondatore offline e rientro con DB riaperto; stessa
copia a due destinatari, ricevute durevoli indipendenti, duplicati senza nuovi
contatori, nuovo membro senza storia retroattiva, modalità incompatibili,
scope/ACK alterati, cancellazione/deadline e fault del commit senza ACK tardivo.
Test mantenuti comuni e Node/TLS/P-256/SQLite reali; evidenze effettive in STATO.

## Continuazione additiva e ownership

Entrambi gli HELLO supportano E richiedono `group-roster-text`,
`group-session-roster`, `group-session-selection`, `group-membership-check`.
Esattamente un ruolo supportato `group-text-sender` o `group-text-receiver`,
opposto sui due endpoint. I ruoli non sono amministrativi. Mismatch rifiutato
prima delle prove; nessun fallback o rilevamento della modalità dal payload.
Il precedente ingresso LTX/LTA resta selezionabile e invariato, anche verso iOS.

Sequenza sullo stesso owner: HELLO → LGM → LSN → LRO → LRA → LTC → testo → LGA.
La continuazione è scelta prima dell'I/O: l'ultimo writer LRA non apre il lettore
EOF del percorso diagnostico. Nessun passaggio di socket, secondo reader, nuovo
timer o nuova autorità dal precedente risultato B5/B7. Verifica OS e SQLite fuori
dal lock; marker esatto, selezione e lifetime ricontrollati ai confini.

Nuovi payload con uint32 big endian, lunghezze esatte prima dell'allocazione:

- **LTC, 324 byte**: ASCII `LTC`, byte versione 1; gruppo, sessione, autore,
  destinatario TLS e SHA-256 dell'intero roster LRO normalizzato concordato,
  cinque ID hex di 64 byte. Entrambi lo costruiscono indipendentemente e
  confrontano tutti i byte. Il minore ID TLS scrive per primo.
- Testo firmato: busta `GROUP_TEXT` esistente, massimo 65536 byte, destinatari
  esattamente uguali all'intero roster, autore uguale al certificato TLS reale.
- **LGA, 360 byte**: ASCII `LGA`, byte versione 1; UUID messaggio 36 byte;
  gruppo, sessione, autore, destinatario TLS e SHA-256 dell'intera busta canonica
  firmata, cinque ID hex di 64 byte. Separato dal dominio LTA; confronto esatto
  della singola busta in attesa, nessuna ricevuta dedotta da EOF.

Il destinatario pubblica Received dopo commit/write ACK, prima del solo cleanup
EOF; il mittente pubblica Sent dopo ACK e ricevuta persistita. Un guasto di cleanup
non annulla un fatto durevole già pubblicato. Used resta conservativo prima di
una scrittura potenzialmente ambigua, sul ricevente soltanto dopo firma valida.
Un commit già entrato può terminare dopo cancel, senza produrre ACK/pubblicazioni
tardivi; il drain precede la chiusura del DB.

## Confini

`GroupTextDeliveryContext` centralizza solo la verifica della busta per i due
ingressi reali; lo scope legacy resta di due membri. `RosterExchange` nel servizio
riusa le stesse prove/unione/installazione di B7. L'archivio, schema 5, firma del
testo e ricevute per destinatario esistenti sono riutilizzati senza migrazioni.
Budget LRO e busta rifiutati interamente, senza troncamenti o limite di prodotto
aggiuntivo. Nessuna nuova libreria, versione, lock o workflow.

Non comprende distribuzione automatica, connessione persistente, recupero da
altri autori, retry/reconnect, paginazione, scelta fra sessioni usate o cronologia
UI completa. Il nuovo ingresso Bonjour/iOS resta il prossimo blocco con lo stesso
core e un checkpoint Native/simulatore. Fase 1/hardware e gate UI restano aperti.
