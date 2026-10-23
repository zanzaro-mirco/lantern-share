# ADR 015 — prerequisito durevole del testo di gruppo

Data: 23 ottobre 2026. Primo sottoblocco tecnico B6, non chat attivata.

## Necessità e utilizzatore

L'archivio TEXT/ACK PoC non contiene gruppo, contatori o destinatari congelati e
ha una sola ricevuta globale. Riutilizzarlo per la chat di gruppo perderebbe
requisiti del prodotto. Rimane invariato e distinto dal nuovo archivio.

`GroupTextReceiver` è il consumer condiviso del nuovo `GroupTextRepository`;
verifica contesto e firma OS, salva, poi produce una prova **locale** di commit.
L'utilizzatore applicativo successivo sarà il nuovo owner di controllo vivo,
NON il pannello o il risultato diagnostico B5. Questo incremento verifica il
percorso codec → firma P-256 → inbox → SQLDelight → riapertura nei test mantenuti,
ma non lo collega a Node, Bonjour o UI. È un prerequisito separato per rendere
verificabili migrazione e atomicità prima del cambio di lifetime del trasporto.

## Modello e compatibilità

`GroupTextContent` conserva ID UUID, gruppo, sessione, autore, sequenza per autore
nel gruppo, tempo logico, testo UTF-8 (massimo 8192 byte) e destinatari ordinati,
distinti e congelati. Il mittente è incluso: la sua copia locale è salvata prima
dell'invio, ma non equivale a ricevute dagli altri. Lo snapshot non è una prova
di appartenenza: deve essere fornito indipendentemente dall'owner autenticato.

I byte firmati sono una sequenza UTF-8 con prefissi di lunghezza, separata dal
PoC dal dominio `lantern-group-text-1`. Comprendono TUTTI i campi, inclusi numero
e identità dei destinatari. La firma OS resta ECDSA SHA-256 DER/Base64. Il codec
JSON rigoroso `GROUP_TEXT` versione 1 è limitato a 65536 byte, rifiuta duplicati,
campi mancanti/sconosciuti, tipi ambigui, UTF-8 invalido e contatori non canonici.
Il test comune fissa i byte canonici, inclusi caratteri multibyte e numeri Long.

Questa busta è nuova e isolata: **nessun owner attuale la accetta sulla rete**.
Non modifica wire 0, HELLO, LGM o LSN e non introduce fallback. Prima del suo uso
su TLS serve una capability obbligatoria distinta e un framing/ACK documentato
che leghi sessione, messaggio e destinatario. Non si presenta il formato locale
come protocollo completo già interoperabile.

## SQLite: schema 5, migrazione 4.sqm additiva

Nuove tabelle separate per messaggio, destinatari/ricevute, contatori e fatto
monotono «sessione utilizzata». Nessuna tabella preesistente è riscritta o
eliminata. Driver, versioni dipendenze e lock restano invariati.

- Riserva durevole di sequenza e tempo logico prima della firma, fuori da callback
  SQL/OS miste. Le cancellazioni possono lasciare buchi: mai riutilizzare numeri.
- Salvataggio atomico di testo, intero snapshot, copia ricevuta localmente,
  avanzamento dei clock e fatto used. Ricevute remote inizialmente assenti.
- ID globale e `(gruppo, autore, sequenza)` univoci. Duplicato esatto idempotente;
  corpo, firma o contesto diversi falliscono senza alterare la copia originale.
  La riprova riutilizza la stessa busta firmata, non una nuova firma casuale.
- Ricevuta limitata a un destinatario congelato e all'intero messaggio salvato;
  sconosciuti e conflitti falliscono anche se l'UPDATE era già partito.
- Primo write della transazione prima delle letture decisionali, anche fra
  connessioni indipendenti. Query di messaggio/destinatari leggono uno snapshot
  transazionale coerente. Overflow dei contatori rifiutato, mai wraparound.
- Fondazione o marker COMMITTATO devono corrispondere a gruppo e identità locale;
  il solo journal pendente non consente scritture. È un controllo di integrità,
  NON verifica OS della membership né permesso al traffico.
- Clock e used restano separati dalla cronologia. Il getter used non elenca
  sessioni attive e non va usato per ripristinarle dopo stop/cambio LAN.

## Confine inbox e ricevuta

Il caller deve serializzare l'inbox con stop/revoca, mantenere aperto il DB,
verificare appartenenze sul TLS effettivo e fornire gruppo/sessione, identità dei
due endpoint e snapshot atteso indipendenti dal messaggio ricevuto. Il callback
OS verifica la firma contro il certificato effettivamente autorizzato, non un
certificato arbitrario allegato. Nessun I/O di rete o firma sotto il lock SQL.

L'inbox ricontrolla il lifetime prima/dopo la verifica e dopo il salvataggio.
Un errore, anche con esito commit incerto, non restituisce ricevuta. Una riprova
identica può confermare la copia già salvata. `GroupTextSavedReceipt` non è un
ACK wire, una firma, una prova remota o un handle di autorizzazione.

Il recupero futuro dovrà verificare separatamente autore, membro che inoltra e
ammissione temporale dei destinatari: questo ingresso diretto richiede invece
autore == peer. Non è un motore di recupero né un'autorizzazione storica.

## Verifica e successivo criterio d'integrazione

Test comuni codec, test JDBC per migrazioni/concorrenza/fault/riapertura e inbox
con P-256/SQLite reali; tre test Native di persistenza predisposti. Evidenze
effettive e checkpoint Apple in STATO, non hardware.

Il prossimo blocco deve collegare questo percorso a un owner TLS ancora vivo con
nuova verifica membership e selezione, snapshot indipendente dei destinatari,
used monotono prima di pubblicare, invio della busta salvata e ACK autenticato
solo dalla ricevuta post-commit. Timer/handover/stop devono essere espliciti:
nessuna riapertura del socket diagnostico B5, assunzione di ACK EOF o consenso
derivato dalla cronologia. Mancano ancora servizio/UI, trasporto/ACK di gruppo,
recupero, reconnect automatico e gestione completa delle sessioni. Nessun requisito
di prodotto è rimosso e nessuna nuova disponibilità fisica è attestata.
