# ADR 006 — ciclo di vita del bootstrap v1 isolato

## Ambito e confine

Incremento del 3 ottobre 2026. `ProtocolHandshakeAttempt`, nel protocollo Kotlin comune, coordina un solo tentativo su una connessione TLS già autenticata. Riusa partecipanti, negoziazione, transcript, APPROVE e verificatore di ADR 004/005. Non apre socket, non gestisce discovery, non genera nonce, non accede a SQLite e non concede trust. Nessun chiamante in `Node`, `PeerConnection` o Swift; il servizio resta wire v0. Nessuna versione, dipendenza, identità o schema modificati.

Il proprietario deve selezionare esplicitamente il candidato prima di TLS, accettare soltanto quel pin e fornire il pin del certificato realmente accettato. La macchina rifiuta una discordanza tra selezione e TLS prima di esporre HELLO; HELLO remoto deve corrispondere allo stesso pin. Il verificatore usa la chiave di quel certificato, non discovery. Nuova connessione = nuovo tentativo con nonce OS freschi; nessun reset, TOFU o fallback v0.

## Avanzamento e conferma

| Stato | Evento che lo fa avanzare |
|---|---|
| `AwaitingHello` | Primo HELLO compatibile e legato al pin TLS |
| `AwaitingConfirmation` | Conferma esplicita dell'utente con il ticket di confronto corrente |
| `SigningApproval` | Callback del signer OS per i byte direzionali di quel ticket |
| `SendingApproval` | Callback di scrittura riuscita dell'APPROVE, non semplice accodamento |
| `AwaitingRemoteApproval` | APPROVE remoto indirizzato correttamente e firma verificata |
| `Ready` | Sono presenti conferma locale, scrittura locale riuscita e prova remota valida |
| `Closed` | Errore, rifiuto tramite cancellazione, scadenza o perdita del canale segnalata dal proprietario |

La prova remota può arrivare dopo HELLO e prima della conferma locale, durante firma/invio o dopo l'invio. I tre stati intermedi indicano separatamente se la prova remota è già verificata. Non si diventa `Ready` solo ricevendo APPROVE. APPROVE prima di HELLO, HELLO ripetuto/alterato, APPROVE ripetuto e ulteriori frame bootstrap dopo `Ready` chiudono il tentativo. Incompatibilità, indirizzi o firme errati sono esiti espliciti, non autorizzazioni implicite.

Il ticket di confronto contiene il transcript completo da mostrare come SHA-256; l'hash rimane responsabilità dell'adattatore OS. La UI deve catturare quel ticket e chiamare `confirm(ticket)` soltanto dopo il confronto esplicito sul dispositivo fisico. Ticket di confronto, firma e invio sono oggetti opachi appartenenti all'istanza: esiti duplicati, obsoleti o di un'altra istanza sono ignorati anche se il peer o il transcript coincidono. Non sono identificativi trasmessi in rete.

Le offerte sono copiate e congelate all'inizio e alla ricezione del primo HELLO. Le viste HELLO, capacità negoziate e array del transcript/firma sono copie difensive: modificarle dall'esterno non cambia i byte verificati. Il signer OS è un adattatore fidato: deve firmare esattamente i byte del ticket; la macchina controlla la sintassi della firma locale, non duplica la crittografia OS. Una scrittura fallita va riportata con `operationFailed(ticket)`; perdita del canale, blocco, arresto e rifiuto con `cancel()`.

## Tempo, callback e ownership

Durata fissa 120 secondi dalla selezione, non dal completamento TLS o dalla ricezione HELLO. `selectedAtMillis` e `nowMillis` devono appartenere allo stesso orologio monotono dell'adattatore. Ogni ingresso e lettura dello stato verifica la scadenza; il confine esatto di 120000 ms è già scaduto. Un timer in ritardo non prolunga la conferma. Orologio decrescente, intervallo oltre `Long.MAX_VALUE` o errore dell'orologio non possono lasciare il tentativo riutilizzabile.

La macchina non è thread-safe: tutte le chiamate, incluse letture, devono essere serializzate sulla coda del proprietario della connessione. Il verificatore è sincrono; errori ed eccezioni, inclusa cancellazione, chiudono il tentativo e sono rilanciati, mai convertiti in successo. Dopo il verificatore si ricontrolla lo stato e il tempo: un callback che annulla il canale o termina oltre scadenza non può ripristinare la prova. Ingresso di un altro frame durante la verifica fallisce chiuso.

Il proprietario resta responsabile di inviare HELLO locale una sola volta prima di instradare frame alla macchina, di decodificare/frammare con i limiti esistenti e di chiudere le risorse dopo errore/cancellazione. La macchina non verifica ancora i callback di invio HELLO, non legge uno stream e non riceve eventi applicativi. Questo è il prossimo confine da implementare, non una promessa già soddisfatta.

`Ready` rimane revocabile e scade: è un esito locale del bootstrap, non completamento atomico distribuito, appartenenza al gruppo o autorizzazione alla chat. Un vecchio snapshot `Ready` non va usato per persistere trust dopo cancellazione/scadenza; il futuro proprietario dovrà ricontrollare il tentativo sul proprio contesto seriale. APPROVE non è una credenziale di gruppo e non deve essere persistito come tale.

## Verifiche e limiti

Test comuni per tutte le quattro collocazioni della prova remota, prerequisiti locali, offerte congelate, ordine e duplicati, pin/indirizzi/incompatibilità/firma, ticket di tentativi precedenti, cancellazione, scadenza esatta anche senza timer, overflow/rollback, errori degli adattatori e callback rientranti. Solo nei test puri si simulano orologio e verificatore.

Quattro `HandshakeV1TlsTest` JVM usano realmente TLS 1.3 reciproco, pin esatti, certificati P-256 e firme JCA, codec bootstrap e macchina: successo bidirezionale con transcript uguale, destinatario estraneo, replay su nonce freschi e callback di scrittura dopo cancellazione locale. Nell'ultimo caso il peer può ricevere i byte e risultare `Ready`, mentre l'istanza cancellata resta `Closed`: evidenza del limite locale, non prova di completamento distribuito. Confronto/conferma utente e ritardo del callback sono simulati soltanto nella fixture; la socket rimane aperta fino al termine dello scambio di test. Nessun repository di trust e nessun collaudo fisico.

Comandi e conteggi effettivi in `STATO_SVILUPPO.md`. CI precedente `4203f42` riuscita anche su iOS; nuova compilazione/test Apple demandati alla CI, non eseguibili da Windows. Hardware rinviato ma obbligatorio in fase 1.

Prossimo incremento: proprietario isolato del bootstrap v1 che instradi codec/macchina e chiuda risorse su errori I/O o cancellazione, con test TLS reali. Ancora senza attivazione in `Node`/Swift, persistenza trust o modifica al canale v0.
