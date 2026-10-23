# ADR 016 — primo trasferimento esplicito di testo di gruppo sul TLS vivo

Data: 23 ottobre 2026. Integrazione Android/desktop di B6.

## Risultato osservabile e confini

Due membri già ammessi scelgono **Invia testo gruppo** e **Ricevi testo gruppo**
nel pannello dedicato. Node usa listener/discovery e selezione esclusiva esistenti,
ma NON il trust, i frame o i messaggi PoC. Prove membership fresche, sessione LAN,
testo firmato e ACK post-commit attraversano lo stesso TLS reciproco. Il pannello
mostra il testo, ID messaggio/sessione e successo soltanto al punto previsto.

È un primo trasferimento diretto, non una chat multipartecipante completa o una
connessione persistente: una busta per tentativo, entro i **120 secondi originali**,
poi chiusura. Nessun handover, timer riarmato, reconnect o ritrasmissione automatica.
Non cambia il requisito finale di una connessione di controllo per coppia, roster
aggiornato, membri offline e recupero. Ingresso Bonjour/iOS ancora da integrare;
non compare una falsa azione iPhone che usi il PoC come fallback.

## Prerequisiti e snapshot dei destinatari

Il servizio legge e verifica la membership COMMITTATA prima del pin e nuovamente
sul TLS effettivo. Radice e marker intero esatto sono ricontrollati durante i
callback OS, prima dei passi durevoli e prima del risultato. B4/B5 precedenti non
sono credenziali. Il certificato usato dall'inbox è quello del peer TLS, non una
chiave contenuta nel messaggio. Ogni membro, incluso un adottato con fondatore
offline, usa lo stesso percorso.

Questo primo ingresso può concordare soltanto lo scope dei due endpoint verificati
di una sessione inizialmente vuota. È uno snapshot di ammissione alla sessione,
non l'elenco dei membri dell'intero gruppo. I due ID sono congelati indipendentemente
dal testo e poi inclusi nella sua firma. Non viene introdotto un limite di prodotto
di due membri: l'espansione del roster autenticato resta un blocco obbligatorio.

Per una sessione già utilizzata, il servizio richiede lo stesso scope mantenuto
nella run con radice/marker/ID esatti. Se manca o differisce, rifiuta con
`ROSTER_REQUIRED`, PRIMA di generare/salvare/inviare la busta: non ricostruisce
destinatari dalla sola coppia corrente, mDNS, cronologia o offerta remota. Anche
un dispositivo rientrato dopo stop può quindi negoziare B5 ma non ancora inviare
su quella sessione usata senza il futuro protocollo di roster. Due sessioni usate
richiedono ancora scelta esplicita, senza fusione. Il limite non va nascosto come
chat di gruppo completa o aggirato generando un ID nuovo nella run corrente.

B5 conserva lo scope noto solo per la stessa sessione/radice/marker; non lo crea
né autorizza il testo. Stop azzera entrambi in memoria; lo storico rimane salvato
ma non riattiva la sessione. Dopo stop di tutti, una nuova sessione ha nuovi ID,
mentre sequenze autore e clock restano durevoli nel gruppo.

## Protocollo opzionale additivo

Entrambi gli HELLO devono supportare E richiedere `group-membership-check`,
`group-session-selection` e **`group-text-transfer`**. I supportedFeatures indicano
esattamente uno fra `group-text-sender` e `group-text-receiver`, opposti sui due
endpoint. I ruoli sono solo instradamento di questo trasferimento, non ruoli
amministrativi o autorità. Mismatch rifiutato PRIMA dell'I/O delle prove.

Sequenza sullo stesso owner: HELLO → LGM verificato → LSN → scope identico sui due
endpoint → una busta `GROUP_TEXT` di ADR 015 → ACK esatto. Nessun EOF reader B4/B5
intermedio o APPROVE bootstrap. Scope e ACK hanno prefisso uint32 big endian con
lunghezza esatta verificata prima dell'allocazione; testo 1..65536 byte, codec
Kotlin comune. Nessuna variazione dei formati precedenti, schema, lock o workflow.

Scope, payload **260 byte**:

- ASCII `LTX`, byte versione 1;
- gruppo, sessione, mittente e destinatario: quattro fingerprint ASCII da 64 byte.

Il minore ID TLS scrive lo scope per primo; l'altro legge, confronta e scrive.
Nessun contatore, firma o salvataggio prima del confronto dello scope remoto.

ACK, payload **360 byte**:

- ASCII `LTA`, byte versione 1;
- UUID messaggio ASCII da 36 byte;
- gruppo, sessione, autore, destinatario e SHA-256 della busta JSON canonica
  completa (firma inclusa): cinque fingerprint ASCII da 64 byte.

L'ACK è autenticato dal TLS vivo, confrontato con TUTTI i byte attesi della singola
busta in attesa e persistito per quel destinatario. Non è firmato per inoltro o
recupero, non viene accettato da un altro canale o dedotto da EOF. L'ultimo writer,
il destinatario, attende EOF entro la deadline per non abortire l'ACK accodato;
il mittente chiude dopo averlo letto/persistito. Dati ulteriori sono rifiutati.
Il destinatario pubblica il proprio fatto durevole dopo commit/write ACK, prima
di attendere EOF: un guasto soltanto nel cleanup non annulla il salvataggio già
attestato localmente. Il mittente pubblica Sent soltanto dopo ACK esatto e
persistenza della ricevuta. Nessuno dei due fatti è un permesso di riuso del canale.

## Persistenza, concorrenza e interruzioni

Il mittente riserva contatori, firma con l'identità OS, verifica limiti/contesto e
salva la busta prima della write. Il destinatario usa `GroupTextReceiver`: controllo
di contesto, firma OS, commit idempotente, poi ricevuta locale dalla quale costruire
l'ACK. Nessun dato PoC modificato, consenso ripristinato o promozione del pendente.

L'inizio del passo durevole è arbitrato con cancel/stop sotto un lock breve, senza
OS, SQLite o rete dentro il lock. Una transazione già iniziata può finire dopo la
revoca; ogni successiva write ACK/pubblicazione richiede ancora lifetime valido.
Il caller resta vivo fino al drain del worker prima di chiudere il repository.
Un risultato DB ambiguo non produce un ACK o un replay. ID tentato presentato come
**copia potenzialmente salvata**, mai come ricezione remota attestata.

La sessione in memoria è marcata used in modo conservativo prima di entrare nella
scrittura (sul ricevente solo DOPO firma verificata), senza reset se questa fallisce
o viene annullata. Ciò impedisce di trattare come vuota una sessione con esito
commit incerto. Può restare divergenza used tra peer dopo un guasto: le regole
esistenti la rifiutano, non cancellano la copia, non abbassano used e non inventano
recovery. Il fatto used durevole è nella stessa transazione del messaggio; non
viene consultato per ripristinare la sessione dopo stop.

## Accettazione e seguito

Regressioni mantenute con Node/TLS/P-256/SQLite veri: entrambi gli ordinamenti,
ammissione e riapertura, direzioni opposte, continuità della run, nuovi ID dopo
stop di tutti e contatori persistenti, delegati col fondatore offline, ruoli/modi
incompatibili, gruppi diversi, scope sconosciuto rifiutato, fault del commit senza
ACK, cancel durante scrittura. Test owner per scope/ACK alterati e cancel/deadline
originale durante attesa ACK; framing esatto, troncamenti, flush e budget di read;
regole e vettori in commonTest. Evidenze effettive in STATO, non hardware.

Prossima integrazione: stesso percorso Bonjour/iOS con codec e regole Kotlin,
scope della run e owner Swift, checkpoint completo Native/simulatore. Roster
multipartecipante, scelta operativa, riconnessione, recupero e UI completa restano
obbligatori e non completati. Nessuna release o collaudo fisico nuovo dichiarato.
