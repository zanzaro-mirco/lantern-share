# ADR 017 — roster autenticato della sessione, primo ingresso Node

Data: 23 ottobre 2026. Seguito circoscritto di B6, blocco B7.

## Risultato e utilizzatore

Due membri già ammessi scelgono **Sincronizza roster** in Android/desktop. Nuove
prove sul TLS selezionato, negoziazione LSN e scambio di attestazioni firmate
producono un elenco locale di partecipanti della sessione, non la presenza online.
Node conserva le attestazioni offline nella run e può trasmetterle a chi rientra,
anche con fondatore offline. Niente lettura della cronologia, scrittura SQLite,
trust PoC, ripristino di consenso o apertura automatica di altri collegamenti.

Utilizzatori reali: pannello condiviso dei partecipanti e guardia del trasferimento
iniziale LTX di ADR 016. Dopo riapertura di un peer, un roster verificato di due
partecipanti ripristina lo scope e consente quel trasferimento nella stessa sessione.
Uno snapshot più ampio non viene ridotto alla coppia corrente: il vecchio LTX
rifiuta prima di contatori/firma/salvataggio, anche se la sessione è ancora vuota.
L'invio con destinatari multipartecipante richiede una continuazione successiva;
questo blocco non dichiara chat di gruppo o recupero completi.

## Prove e conoscenza della run

Ogni attestazione `GroupSessionJoin` contiene gruppo/fondatore/sessione/identità,
certificato pubblico del partecipante, prova membership LGM e firma del partecipante
sull'intero prefisso canonico. La prova LGM contiene i certificati degli emittenti;
quello del membro finale è separato, non ricavato da un campo del messaggio.
Il verificatore OS controlla pin DER esatto, validità e firme dell'intera catena,
poi la firma propria. Radice/sessione locali indipendenti, nessuna radice adottata
dal roster. Il record del peer selezionato deve inoltre contenere esattamente il
certificato del TLS effettivo. Un record valido non abilita un pin o un nuovo TLS.
La cache OS per invocazione ricontrolla il DER anche quando un'identità è già
presente: catene successive non possono sostituire i byte pubblici saltando il pin.

L'unione è monotona per la stessa radice/sessione e conserva gli offline. Le
attestazioni sono ordinate per identità; se due record validi rappresentano lo
stesso membro, si mantiene il minimo lessicografico dei byte canonici completi.
Ciò rende deterministica l'unione anche con firme ECDSA ripetute differenti.
Identità duplicate dentro un singolo payload vengono invece rifiutate.
Tutte le prove, anche quelle offline già mantenute, sono riverificate a ogni
sincronizzazione; scadenza/guasti OS non causano la loro omissione silenziosa.

Il flag `retainedSnapshot` dichiara che il membro TLS conserva già lo snapshot
della sessione. È metadato autenticato dal canale, non prova di appartenenza o
consenso globale: l'elenco rimane conoscenza locale monotona, non consenso bizantino
o presenza globale simultanea. Un partecipante di una sessione usata con scope
sconosciuto può contribuire la propria attestazione, ma **due peer che hanno perso
entrambi lo snapshot non possono ricostruirlo dalle sole firme nuove**.
Serve almeno uno snapshot mantenuto; altrimenti `MISSING_PARTICIPANTS`.

Prima di concordare il risultato ogni owner richiede che l'unione copra TUTTI i
propri partecipanti noti. Nel passaggio dal vecchio LTX può esserci uno scope di
due membri senza attestazioni roster: il contatto con entrambi produce le firme
mancanti. Se uno è offline e non ha mai prodotto la propria attestazione, l'ingresso
di un terzo fallisce anziché dimenticarlo o firmare al suo posto. Nessuna firma
ricostruita dalla cronologia, nessun destinatario retroattivo nei testi già salvati.

Stop elimina memoria e attestazioni della run, non copie e destinatari durevoli
dei messaggi. Se un altro peer conserva la sessione, il rientrante recupera da
quello dopo nuove prove; se tutti si fermano nasce un nuovo ID, mai ripristinato
da SQLite. La convergenza fra sessioni vuote non trasferisce attestazioni firmate
per un ID diverso; due sessioni usate richiedono ancora scelta esplicita.

## Protocollo opzionale additivo

Entrambi gli HELLO supportano E richiedono `group-membership-check`,
`group-session-selection` e la nuova **group-session-roster**. Nessun ruolo
amministrativo. I percorsi B4, B5, LTX/LTA e wire 0 restano identici; nessuno sniffing
o fallback. L'iOS attuale non espone questa nuova azione, il suo testo ADR 016 resta
compatibile con quello Node. Schema/versioni/lock/workflow invariati.

Stesso owner/pin/TLS e deadline originale: HELLO → LGM verificato → LSN → LRO → LRA.
Il minore pin TLS scrive per primo in ogni fase; nessun EOF reader intermedio.

Ogni payload ha uint32 big endian di lunghezza. Snapshot LRO massimo **4 MiB**,
verificato prima dell'allocazione; record limitato dalla somma dei limiti LGM,
certificato Base64 e firma già esistenti. Lunghezze/counter unsigned, letture esatte,
UTF-8 rigoroso, troncamenti/flag sconosciuti/byte finali rifiutati. Il budget è del
primo scambio, non un limite di prodotto al numero dei membri: oltre budget si
rifiuta senza troncare; paginazione per snapshot più grandi ancora da realizzare.

Snapshot, prefisso **201 byte**:

- ASCII `LRO`, versione byte 1;
- gruppo, fondatore e sessione, tre ID ASCII da 64 byte;
- retainedSnapshot: byte 0 oppure 1;
- numero di record: uint32 big endian, non nullo e compatibile col budget residuo;
- per ogni record: uint32 di lunghezza e record LSJ.

Record LSJ:

- ASCII `LSJ`, versione byte 1;
- gruppo/fondatore/sessione/membro: quattro ID ASCII da 64 byte;
- lunghezza uint32 + certificato Base64 UTF-8;
- lunghezza uint32 + prova binaria LGM;
- lunghezza uint32 + firma Base64, massimo 256 byte.

I byte firmati sono l'intero record fino alla prova LGM inclusa, ESCLUSI il campo
lunghezza/firma finale. Magic/versione separano questo dominio dagli altri formati.
Il codec Kotlin comune possiede tutti i byte, non esiste un codec OS alternativo.

Accordo LRA, payload esatto **196 byte** verificato prima dell'allocazione:
ASCII `LRA`, versione 1, gruppo/sessione/SHA-256 dell'intero roster normalizzato,
tre stringhe hex da 64 byte. Si confrontano tutti i byte attesi sul TLS vivo.
Entrambi verificano e uniscono prima dell'accordo, poi installano soltanto la
propria vista. LRA non è ricevuta di messaggi, prova di installazione remota o
commit distribuito. L'ultimo writer attende EOF per preservare i byte accodati;
un errore nel solo cleanup non annulla la vista locale già concordata/installata.

## Lifecycle e verifica

Preflight committato prima del pin e nuove prove sul canale. Radice, marker intero,
selezione e deadline ricontrollati prima/dopo OS e prima dell'installazione. OS,
framing, hash e rete fuori dal lock di stato; pubblicazione/memoria arbitrate con
cancel/stop sotto lock breve. Callback vecchi non installano risultati. Nessun
contatore o messaggio viene creato dalla sincronizzazione; used viene mantenuto
dalla selezione LSN e non azzerato dalla chiusura del pannello.

Regressioni comuni: codec, negoziazione obbligatoria, firme/binding indipendenti,
unione deterministica senza perdita, conteggi/flag/limiti/troncamenti/duplicati.
Regressioni Node/TLS/P-256/SQLite reali: riapertura di entrambi i ruoli, continuità
di sessione e contatori, tre membri con due passaggi offline, nessun destinatario
retroattivo, scope legacy senza prove e perdita di tutti gli snapshot rifiutati,
modalità/radici incompatibili, assenza gruppo, cancel/riselezione. Test owner con
firma, radice, sessione e accordo alterati; cancel/deadline originale in attesa
LRA, framing esatto/flush/budget. Evidenze effettive in STATO, non hardware.
Regressione mantenuta anche per sostituzione DER dopo un certificato già verificato
nella stessa cache, senza modifiche ai criteri di ammissione o nuove CA.

**Prossimo blocco unico:** dopo CI conclusa/correzioni, stesso ingresso Bonjour/iOS
con le regole Kotlin e owner Swift, checkpoint Native/simulatore raggruppato.
Invio con snapshot multipartecipante, recupero, scelta operativa, riconnessione e
UI completa restano obbligatori. Nessuna chiusura della fase 1 o release.
