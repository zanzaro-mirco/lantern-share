# ADR 005 — transcript e verifica remota v1 isolati

## Ambito

Incremento del 3 ottobre 2026, durante la sessione autonoma richiesta dall'utente. Introduce byte canonici, payload HELLO e verifica della conferma remota nel Kotlin comune. Non introduce un handshake di rete, un gruppo, credenziali di ammissione o autorizzazione ai messaggi. Il servizio continua a usare esclusivamente wire v0; identità, SQLite, versioni e lock restano invariati.

## Partecipanti e HELLO

`ProtocolHandshakeParticipant` contiene identità, nonce e una copia delle capacità. Identità e nonce sono esattamente 64 caratteri esadecimali minuscoli: l'identità mantiene la semantica del pin SHA-256 del certificato; il nonce rappresenta 256 bit. La sintassi non prova né possesso della chiave né casualità/freschezza del nonce. L'adattatore dovrà generare nuovi nonce crittograficamente casuali per ogni connessione.

`ProtocolHandshakeHelloCodec` codifica un payload con tre campi obbligatori, nell'ordine canonico `identity`, `nonce`, `capabilities`. Il valore annidato usa esattamente il serializer di ADR 004: nessuna seconda implementazione delle regole delle capacità. Tutti i campi, anche quelli annidati, rifiutano duplicati e nomi sconosciuti; identità/nonce devono essere stringhe. Limite del payload: 4608 byte UTF-8, verificato prima del parsing. Ordine e whitespace in ingresso sono liberi; la codifica li normalizza. Non è ancora un envelope con versione/tipo instradabile dal trasporto.

## Transcript canonico

Per due identità distinte, i partecipanti sono ordinati lessicograficamente per identità. Ogni campo è codificato come `lunghezzaDecimaleUTF8:valore`, concatenando, in ordine:

1. `lantern-handshake-1`;
2. identità minore, il suo nonce, la sua offerta JSON canonica;
3. identità maggiore, il suo nonce, la sua offerta JSON canonica.

Si lega l'intera offerta, non soltanto l'intersezione delle capacità: modificare anche una capacità opzionale deve invalidare la conferma. L'ordinamento evita dipendenza dal ruolo client/server; invertire i partecipanti non cambia il transcript. Le lunghezze rendono inequivocabili i confini, anche in presenza di `:` nei valori JSON. Si firma la rappresentazione canonica ricostruita, non il whitespace ricevuto.

Il futuro codice di confronto è SHA-256 di questi byte. Vettore verificato indipendentemente con .NET e JCA:

- identità `a` ripetuta 64 volte, nonce `1` ripetuto 64 volte, offerta `{"version":1,"supportedFeatures":["receipts","text"],"requiredFeatures":["text"]}`;
- identità `b` ripetuta 64 volte, nonce `2` ripetuto 64 volte, offerta `{"version":1,"supportedFeatures":["text"],"requiredFeatures":[]}`;
- transcript: 441 byte;
- SHA-256: `fb8a622679fac33a9fab0be883ad13c24ff8c5bd2be409fde23765c70022f87f`.

## Conferma direzionale e verifica

`approvalBytes(sender, recipient)` usa la stessa codifica a lunghezze, con campi `lantern-handshake-approve-1`, identità mittente, identità destinatario, transcript completo. Il dominio distinto impedisce riuso delle firme v0 o della firma del solo transcript; le identità direzionali impediscono di riflettere la conferma di A come conferma di B. Le firme restano ECDSA SHA-256 tramite le API OS, non implementate nuovamente in Kotlin comune.

`ProtocolHandshakeVerification.verifyRemoteApproval` richiede il pin del certificato TLS effettivamente accettato sulla connessione corrente, distinto dall'identità locale. Rifiuta HELLO discordante dal pin, versioni/capacità incompatibili, firma con codifica non valida e firma non verificata sui byte direzionali `remote → local`. L'overload per il payload APPROVE verifica anche emittente/destinatario prima di invocare il verificatore. L'adattatore fornisce il verificatore legato alla chiave di quello stesso certificato, non a un certificato trovato tramite discovery. Gli errori inattesi dell'adattatore sono propagati: non diventano successi.

Il risultato `Verified` significa soltanto che la conferma remota attesta quelle offerte. Non prova la consegna della conferma locale, non sostituisce confronto/conferma esplicita dell'utente, non scrive trust e non abilita testo. La macchina isolata introdotta in [ADR 006](ADR-006-STATO-HANDSHAKE-V1.md) congela offerte e gestisce conferma locale, scadenza, cancellazione e ticket per callback obsoleti. Il futuro proprietario della connessione dovrà integrarla e gestire risorse/completamento dell'associazione. Questa prova non è una credenziale di gruppo e non va salvata come tale. Nessun fallback automatico a v0.

## Limiti del parser e regressione

La revisione avversaria ha riprodotto uno `StackOverflowError` nel codec precedente con array annidati, pur entro il limite di byte. `decodeBoundedProtocolJson` limita la profondità prima della deserializzazione: massimo 2 contenitori per un'offerta, 3 per HELLO (oggetto, capacità, array). Ignora i delimitatori nelle stringhe e gestisce gli escape; non sostituisce il parser JSON. Il controllo è condiviso soltanto dai nuovi codec v1, senza modificare `Wire` v0. La regressione richiede un errore di input, non permette di mascherare un errore di runtime con `assertFails` generico.

## APPROVE e bootstrap versionato

La seconda sessione autonoma aggiunge `ProtocolHandshakeApproval` e il codec del payload: tre stringhe obbligatorie `sender`, `recipient`, `signature`, emittente/destinatario distinti e validi, massimo 1024 byte. La firma usa Base64 standard canonico, da 4 a 256 caratteri, con padding quando necessario e bit inutilizzati a zero. Sono rifiutati whitespace, alphabet URL-safe, padding incompleto/intermedio e spellings alternativi degli stessi byte. La validità DER/ECDSA resta compito dell'adattatore; superare il controllo sintattico non prova la firma. Una prova JVM confronta la validazione con il Base64 JDK per tutte le dimensioni 1–192 byte e verifica il rifiuto degli alias nei pad bit.

`ProtocolHandshakeFrameCodec` definisce soltanto l'envelope di bootstrap, non il formato completo degli eventi/messaggi/sessioni v1. Varianti:

```json
{"version":1,"type":"HELLO","hello":{...}}
{"version":1,"type":"APPROVE","approval":{...}}
```

Gli oggetti indicati con `...` sono esattamente i payload già definiti. È richiesto uno solo dei campi `hello`/`approval`, coerente con `type`; null, combinazioni contraddittorie, altri tipi, campi sconosciuti/duplicati e versioni bootstrap diverse dall'intero numerico `1` sono rifiutati. I nomi distinti dei payload permettono decodifica strutturale in qualsiasi ordine senza trasformare prima gli oggetti in mappe che perdano i duplicati. I serializer annidati sono quelli dei codec esistenti. La versione del bootstrap è distinta dalla versione offerta: una futura versione nelle capacità è rappresentabile, ma il negoziatore attuale la rifiuta.

Limiti di parsing, comprensivi del contenitore radice:

| Codec isolato | Byte massimi | Profondità contenitori |
|---|---:|---:|
| Capacità | 4096 | 2 |
| HELLO | 4608 | 3 |
| APPROVE | 1024 | 1 |
| Envelope bootstrap | 5120 | 4 |

Quando un payload è annidato nell'envelope si applica il limite complessivo dell'envelope, anche al whitespace; restano in vigore tutti i vincoli dei modelli. Nessun codec viene instradato da `Wire`, `Node`, `FrameStream` o dal servizio Swift. La messa in rete del v1 e la compatibilità con installazioni v0 richiedono un incremento esplicito successivo; non fare fallback dopo un rifiuto.

## Verifiche e prossimo passo

Test comuni per vettori byte, simmetria, direzione, alterazioni di identità/nonce/offerte, copia degli input, HELLO positivo/negativo/limiti, pin discordante, incompatibilità, firma invalida ed eccezioni del verificatore. I test di regola usano un verificatore simulato solo nei test; tre test JVM usano firme ECDSA reali e SHA-256 JCA, con identità di fixture, senza pretendere di provare TLS o keystore.

`HandshakeV1TlsTest` aggiunge tre prove con socket TLS 1.3 reali, certificati P-256 e pin esatti reciproci, HELLO/APPROVE attraverso l'envelope e verifica con la chiave del certificato della connessione: conferma bidirezionale/digest uguale, destinatario estraneo rifiutato e vecchia firma rifiutata su un nuovo collegamento con nonce freschi. Chiavi PKCS#12 e passphrase sono fixture temporanee, ripulite a fine test; nessun trust-all, repository del prodotto o credenziale reale. Il framing a lunghezze è solo del test; non modifica quello attivo v0. Queste prove non dimostrano associazione con confronto fisico, persistenza di trust o interoperabilità Apple.

Verificati localmente JVM, metadata comuni, unit test della variante Android e build APK. La CI `4203f42` con i codec e i tre test TLS è tutta riuscita, iOS inclusa. L'incremento successivo usa la macchina di ADR 006 negli stessi test TLS e aggiunge una quarta prova di callback dopo cancellazione. Nessun nuovo collaudo fisico. I risultati numerici e i comandi sono in `STATO_SVILUPPO.md`.

La macchina del solo handshake è ora implementata e verificata localmente, ancora senza collegamento al servizio o persistenza del trust. Prossimo incremento circoscritto: proprietario del bootstrap isolato che instradi codec/macchina e gestisca errori I/O/cancellazione, come precisato in ADR 006. Il v1 di prodotto (eventi, gruppi, sessioni, recupero, trasferimenti) rimane da completare.
