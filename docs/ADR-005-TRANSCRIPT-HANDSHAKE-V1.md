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

`ProtocolHandshakeVerification.verifyRemoteApproval` richiede il pin del certificato TLS effettivamente accettato sulla connessione corrente, distinto dall'identità locale. Rifiuta HELLO discordante dal pin, versioni/capacità incompatibili, firma vuota/oltre 256 caratteri e firma non verificata sui byte direzionali `remote → local`. L'adattatore fornisce il verificatore legato alla chiave di quello stesso certificato, non a un certificato trovato tramite discovery. Gli errori inattesi dell'adattatore sono propagati: non diventano successi.

Il risultato `Verified` significa soltanto che la conferma remota attesta quelle offerte. Non prova la consegna della conferma locale, non sostituisce confronto/conferma esplicita dell'utente, non scrive trust e non abilita testo. Il futuro proprietario della connessione dovrà mantenere offerte congelate e gestire conferma locale, scadenza, cancellazione, callback obsoleti e completamento dell'associazione. Questa prova non è una credenziale di gruppo e non va salvata come tale. Nessun fallback automatico a v0.

## Limiti del parser e regressione

La revisione avversaria ha riprodotto uno `StackOverflowError` nel codec precedente con array annidati, pur entro il limite di byte. `decodeBoundedProtocolJson` limita la profondità prima della deserializzazione: massimo 2 contenitori per un'offerta, 3 per HELLO (oggetto, capacità, array). Ignora i delimitatori nelle stringhe e gestisce gli escape; non sostituisce il parser JSON. Il controllo è condiviso soltanto dai nuovi codec v1, senza modificare `Wire` v0. La regressione richiede un errore di input, non permette di mascherare un errore di runtime con `assertFails` generico.

## Verifiche e prossimo passo

Test comuni per vettori byte, simmetria, direzione, alterazioni di identità/nonce/offerte, copia degli input, HELLO positivo/negativo/limiti, pin discordante, incompatibilità, firma invalida ed eccezioni del verificatore. I test di regola usano un verificatore simulato solo nei test; tre test JVM usano firme ECDSA reali e SHA-256 JCA, con identità di fixture, senza pretendere di provare TLS o keystore.

Verificati localmente JVM, metadata comuni, unit test della variante Android e build APK. Compilazione/test Apple e CI del nuovo codice pendenti, nessun nuovo collaudo fisico. I risultati numerici e i comandi sono in `STATO_SVILUPPO.md`.

Prossimo incremento circoscritto: payload APPROVE v1 rigoroso che trasporti emittente, destinatario e firma, con test di round-trip, indirizzamento e limiti, ancora senza attivazione nel trasporto. Envelope/versionamento di rete e macchina di associazione richiedono passaggi ulteriori.
