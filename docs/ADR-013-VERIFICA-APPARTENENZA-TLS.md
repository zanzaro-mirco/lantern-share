# ADR 013 — verifica esplicita dell'appartenenza su TLS

> **Stato riconciliato al 25 ottobre 2026:** B4 integrato e verificato automaticamente su Node e Bonjour/iOS, Apple 80710c6 / 168 XCTest complessivi. Risultato diagnostico non riusabile per B5–B8: ciascuno ripete la prova sul proprio TLS. Collaudo fisico aperto. [Evidenze correnti](../STATO_SVILUPPO.md); [indice documentale](STATO_DOCUMENTAZIONE.md). Date, conteggi e “prossimi passi” originari sotto conservano il loro ambito storico.

Data: 19 ottobre 2026. Decisione tecnica additiva per il blocco B4; nessuna modifica
alla politica A, ai dati esistenti o alle autorizzazioni della prova tecnica.

## Obiettivo e confini

Un membro già ammesso verifica l'appartenenza del peer, senza emettere una nuova
delega, chiedere un altro confronto o dipendere dal fondatore online. Il primo
utilizzatore è Node Android/desktop, azione **Verifica membro** su entrambi. iOS
segue nel blocco B4, non viene dichiarato supportato da una facciata isolata.

È una verifica diagnostica locale, non un canale di sessione, un ACK remoto o una
promozione a trust PoC. Il socket viene chiuso al termine. Il risultato presentato
non è un ticket riutilizzabile: una futura sessione dovrà autenticarsi sul proprio
trasporto vivo e arbitrare identità, gruppo e blocchi. Non si aggiungono reconnect,
scansione automatica, cronologia, uscita dal gruppo o revoche globali.

## Autenticazione

- Selezione esplicita prima del TLS, pin selezionato esclusivo, validità/curva/
  autofirma/pin del certificato verificati dalle policy OS esistenti. HELLO sullo
  stesso canale lega le offerte agli endpoint TLS e conserva i 120 secondi originali.
- Il produttore locale legge soltanto fondazione o marker COMMITTATO. Per un adottato
  verifica catena e due conferme storiche, oltre a DER e identità OS correnti. Niente
  lettura/promozione del pendente. Controllo prima di abilitare TLS e di nuovo prima
  dell'invio: le credenziali possono scadere durante la selezione.
- Il destinatario verifica la prova contro la propria radice durevole indipendente
  e il pin del peer mutual-TLS, non contro i valori appena ricevuti. Un fondatore
  presenta la propria identità, non una self-admission. Un adottato presenta la
  catena fino a SE STESSO, non una nuova credenziale verso il verificatore.
- Copiare la prova di un membro non basta: il certificato TLS deve corrispondere al
  destinatario finale. TLS prova il possesso della relativa chiave sul canale vivo;
  la catena prova la delega. Non serve una nuova primitiva/firma di freschezza del
  credential persistente, né vengono riciclati APPROVE/GROUP_CONFIRM come consenso.
- Firme storiche valide non costituiscono un nuovo permesso di commit; il controllo
  non scrive mai membership, journal, trust o messaggi.

## Formato opzionale, compatibilità

HELLO deve negoziare `group-membership-check` in supportedFeatures E requiredFeatures
di entrambi, prima di leggere questi byte. Nessuno sniffing, fallback al PoC o
interpretazione di un invito come appartenenza. I vecchi peer rifiutano la feature
richiesta, anziché consumare un formato sconosciuto. Wire 0, HELLO, GROUP_EVIDENCE,
GROUP_CONFIRM, firme canoniche e SQLite rimangono invariati; nessuna migrazione.

Payload binario `LGM` seguito dalla versione byte 1, incapsulato nel consueto frame
uint32 big endian. Limite 262341 byte, minimo 197, validati prima dell'allocazione.

| Offset | Contenuto |
|---|---|
| 0 | `LGM` + byte versione 1, quattro byte totali |
| 4, 68, 132 | gruppo, fondatore, membro: ciascuno esattamente 64 byte ASCII hex minuscoli |
| 196 | modo: 0 fondatore, 1 adottato; altri valori rifiutati |
| 197 | solo modo 1: intero GROUP_EVIDENCE JSON esistente, fino alla fine del payload |

Modo 0 richiede membro=fondatore e nessun byte residuo; modo 1 richiede radice coerente
e ultimo destinatario uguale al membro. Non include il certificato del membro perché
quello autorevole è già l'endpoint TLS. Il JSON annidato mantiene regole di duplicati,
UTF-8, profondità, catena e certificati esatte, senza nuove normalizzazioni.

## Ownership e concorrenza

Lo stesso owner bootstrap esegue lo scambio, mantenendo timer, socket e cancellazione.
Chi ha il pin minore invia per primo; l'altro riceve poi invia: due payload massimi
non si bloccano reciprocamente sui buffer TCP. Letture esatte, nessun overread.
Chi scrive l'ultima prova resta vivo fino alla chiusura del primo dopo lettura/verifica:
un close abortivo immediato potrebbe perdere byte TLS accodati. Solo attesa EOF, nessun
ACK nuovo o dato applicativo; un byte successivo rifiuta il percorso. Restano timer
e cancellazione originali, e l'EOF non attesta l'esito della verifica remota.
Controllo della deadline prima di OGNI lettura. Close/scadenza abortiscono anche un
receive pendente, senza attendere il lock dell'I/O. Dopo lo scambio sono inerti i
vecchi confronti bootstrap e l'handover verso l'ammissione: nessun cambio di modalità.

Node riusa la selezione esclusiva già esistente e drena prima i socket PoC. Prima
della pubblicazione ricontrolla owner vivo, deadline, radice e marker completo esatto.
Cancel/blocco/stop o risultato tardivo non possono pubblicare un vecchio successo.
Le operazioni restano fuori dalla UI; DB vivo fino alla chiusura/join del nodo.

## Evidenze

Test comuni di formato/binding/marker e test mantenuti con veri Node, TLS/P-256 e
SQLite riaperto: fondatore↔adottato e adottato↔adottato senza fondatore, ordinamenti
opposti, radici diverse, modalità incompatibili, prova locale corrotta, nessun trust
o nuovo commit. Owner con cancel/scadenza durante lettura TLS e rifiuto dei vecchi
ticket/handover. Comandi, risultati effettivi e limiti Apple/hardware in STATO.

## Integrazione iOS — 20 ottobre 2026

BonjourProbe usa la stessa selezione opaca per invito o controllo membership, mai
due owner paralleli. GroupAdmissionSession verifica il materiale committato fuori
dalla UI e il servizio abilita il pin solo dal callback onPrepared; errori prima
di quel punto non abilitano TLS. Sono invariati selezione esclusiva, sospensione
PoC e drain cumulativo prima della chiusura SQLite.

HandshakeV1Channel conserva socket, timer e callback durante l'intero controllo;
nessun trasferimento al trasporto applicativo o all'ammissione. La facciata Kotlin
verifica i requisiti di entrambi gli HELLO e decide l'ordine comune anche al JVM.
Swift muove byte entro nextReadBytes, conferma la send soltanto da contentProcessed,
rifiuta EOF prematuro/overread e attende unicamente EOF dopo l'ultima write. Non
duplica framing, serializzazione, catena o firme in Swift. La verifica OS conserva
gli errori originali e un errore callback interrompe Kotlin prima della pubblicazione.

L'esito passa a un Flow separato e al pannello condiviso. Identità/selezione/marker
e deadline sono ricontrollati prima di Verified; niente ripresa del consenso o
incremento della revisione di membership. Termine EOF/cancel successivo non cambia
una diagnosi già compiuta in una falsa attestazione remota; una selezione chiusa
non può essere riattivata dal callback tardivo. Nuova integrazione implementata,
compilazione/runtime Apple attestati sul checkpoint 80710c6 / 39473042848, 168
XCTest complessivi senza fallimenti; non hardware. Evidenze correnti in STATO.
La continuazione di sessione successiva è un percorso esplicito distinto descritto
in [ADR 014](ADR-014-NEGOZIAZIONE-INIZIALE-SESSIONE.md), non riuso del risultato B4.
