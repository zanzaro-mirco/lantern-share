# Architettura e qualità del codice

Documento operativo di Lantern, complementare a `PIANO_SVILUPPO.md`. Non sostituisce la specifica né amplia la roadmap. Revisione iniziale: 27 settembre 2026.

## 1. Ruolo e responsabilità

Opero nel ruolo di sviluppatore Kotlin/KMP e software architect senior. Per ogni incremento devo produrre codice comprensibile, scelte motivate ed evidenze riproducibili. La qualità si valuta su proprietà osservabili del software.

Come sviluppatore curo implementazione, nomenclatura, gestione degli errori, test e strumenti di build. Come architect curo confini dei moduli, dipendenze, contratto di protocollo, evoluzione dei dati, ciclo di vita e conseguenze delle scelte sulle cinque piattaforme, incluso Mac Intel e Apple Silicon.

## 2. Come procederò a ogni incremento

1. Leggere specifica, istruzioni e stato reale; identificare comportamento atteso, rischi e target verificabili.
2. Individuare il componente proprietario della regola. Introdurre una nuova interfaccia solo quando isola I/O, una piattaforma o una responsabilità effettivamente distinta.
3. Per una correzione significativa, aggiungere un test che riproduca il problema. Per un refactoring, proteggere prima i contratti esistenti e aggiungere test per i confini appena esplicitati.
4. Modificare per passi compilabili; mantenere formato wire e dati esistenti, oppure introdurre esplicitamente versione e migrazione. Non confondere refactoring con nuove funzionalità.
5. Rivedere concorrenza, risorse, input non attendibile, autorizzazioni e gestione degli errori oltre al percorso positivo.
6. Eseguire test e build pertinenti; aggiornare README, decisioni e `STATO_SVILUPPO.md` con risultati, limiti e prossimo passo. Nessun target è verificato solo perché dichiarato in Gradle.

## 3. Confini e dipendenze

| Componente | Responsabilità | Non deve contenere |
|---|---|---|
| `domain` | Modelli, contratti dei repository, limiti del prodotto, regole pure | SQL, socket, widget, API Android/Apple |
| `protocol` | Formato dei frame, validazione, dati canonici firmati | UI, driver database, gestione del servizio |
| `persistence` | Query SQLDelight e adattatore dei repository, apertura JDBC separata | Decisioni di pairing o trasporto |
| `connectivity` | Ciclo di vita del nodo, autorizzazione, canale TLS e discovery desktop | Composables, importazione di sorgenti dalle app |
| `ui` | Stato presentato e componenti Compose con callback | SQL o accesso diretto ai socket |
| App di piattaforma | Composizione delle dipendenze e ciclo di vita nativo | Duplicazione del protocollo condiviso |

Direzione principale: app → UI/connettività/persistenza → protocollo/dominio. Il motore dipende dai contratti dei repository, l'app fornisce l'adattatore SQLDelight. Gli adattatori JVM e Android sono source set di moduli KMP con dipendenze Gradle dichiarate; niente `../altroModulo/src`.

`Node` coordina il servizio. `PeerConnection` governa un singolo canale già autenticato da TLS. `PairingAuthorization` custodisce la selezione temporanea e la sua scadenza; consente di distinguere permesso di handshake e autorizzazione applicativa. `FrameStream` delimita e valida i buffer. Questa separazione rende possibile modificare una responsabilità senza riscrivere le altre.

Non applicherò Clean Architecture come una serie obbligatoria di livelli. Non serve un use case per ogni getter, un repository generico universale o un contenitore DI per pochi costruttori. La composizione esplicita rimane sufficiente finché il numero di dipendenze lo consente.

## 4. Convenzioni Kotlin

- Nomi legati al dominio, visibilità minima, parametri nominati quando chiariscono l'intento.
- Una responsabilità per funzione; estrarre quando esistono una regola o un passaggio con un nome utile. Nessun limite arbitrario di righe che frammenti la lettura.
- Evitare istruzioni multiple sulla stessa riga, flag booleani di configurazione opachi e stringhe per discriminare casi finiti. Usare enum/sealed type e `when` esaustivi.
- Costanti e validazioni condivise per limiti reali; niente duplicazioni fra UI e trasporto. Le verifiche nel motore restano obbligatorie anche se la UI disabilita un pulsante.
- Immutabilità delle viste pubbliche; mutabilità confinata al proprietario dello stato.
- Commenti per motivazioni, vincoli o invarianti, non per tradurre ogni istruzione. Documentare soprattutto ownership, thread e persistenza.
- Dipendenze e plugin mantenuti nel catalogo/lock esistenti; questo refactoring non richiede aggiornamenti di versione.

## 5. Concorrenza e risorse

Ogni socket ha un proprietario e viene chiuso anche in caso di frame errato, perdita di rete o arresto. I callback di una precedente attivazione non devono aggiornare lo stato della nuova. Una selezione di pairing è uno stato atomico, non due variabili indipendenti. I timeout locali usano tempo monotono; le date dei certificati continuano a usare il calendario.

La cancellazione di coroutine va rilanciata, non trasformata in errore di rete. Gli errori attesi sono gestiti al confine del servizio; le eccezioni di programmazione non diventano silenziosamente successi. Gli errori di cleanup non devono impedire la chiusura delle altre risorse.

Il trasporto JVM usa ancora socket bloccanti confinati a `Dispatchers.IO`. Il ciclo di vita sincrono e alcuni ingressi UI richiedono ulteriore lavoro prima di un servizio in background: non basta estrarre una classe per dichiarare risolti tutti i problemi di concorrenza. Il proprietario dell'app chiude prima il nodo, poi il database.

## 6. Protocollo, persistenza e sicurezza

Il refactoring conserva versione wire 0, nomi JSON, ordinamento dei campi firmati e schema SQLite. I tipi interni possono migliorare senza modificare il formato. Una futura modifica incompatibile richiederà negoziazione/versionamento e vettori di interoperabilità.

La selezione di un candidato abilita soltanto l'handshake con il suo pin. La promozione a peer autorizzato richiede conferme e firma verificate; scadenza, blocco o rifiuto annullano la selezione. La ricevuta segue il commit SQLite. Deduplicazione e controllo dei conflitti devono stare nella stessa transazione.

Nessun algoritmo crittografico inventato, trust-all, mock di produzione, chiave nei log o recovery che autorizzi implicitamente un peer. Il formato `Frame` è un DTO di protocollo, non il modello definitivo del prodotto. Le lacune di iOS, del Keychain Mac e del gruppo restano dichiarate.

## 7. Strategia di verifica

| Livello | Verifica |
|---|---|
| Regole pure | Limiti, tipi dei frame, transcript, backoff, scadenza/rifiuto del candidato |
| Adattatori | Framing troncato/oversize, SQLite e idempotenza, identità persistente |
| Integrazione | Socket TLS veri, firme, doppia conferma, invio/ricevuta, riavvio del servizio e blocco |
| Rete locale | mDNS reale opt-in; mai equivalente al collaudo hardware |
| Build | JVM/Windows e Android su questo host; CI/preparazione per i target Apple/Linux |

I test devono verificare un contratto o una regressione, non ripetere riga per riga l'implementazione. L'orologio finto è confinato ai test della scadenza; il percorso end-to-end continua a usare crittografia, socket e SQLite reali.

Comandi aggiornati e risultati effettivi in README e STATO. Formattazione/analisi automatica aggiuntiva potrà essere introdotta con versione verificata e configurazione condivisa; non viene dichiarata presente prima di averla integrata in CI.

## 8. Criteri di revisione e completamento

Un incremento è pronto quando comportamento e responsabilità sono spiegabili; le dipendenze rispettano i confini; input e stati illegali sono gestiti; le risorse sono rilasciate; i test pertinenti passano; le build disponibili passano; modifiche del contratto sono esplicite; documentazione e limiti corrispondono al codice.

La revisione non misura qualità dal numero di classi né promette assenza di bug. Non si dichiarano completati pairing distribuito recuperabile, service Android, trasporto iOS o integrazioni Mac soltanto perché l'architettura li rende più facili da aggiungere.

## 9. Registro delle decisioni iniziali

| Decisione | Motivazione | Conseguenza |
|---|---|---|
| Source set JVM/Android espliciti | Eliminare inclusione dei sorgenti di un altro modulo | Test con `:connectivity:jvmTest`; varianti Android compilate da Gradle |
| Repository dietro contratti di dominio | Disaccoppiare il motore da SQLDelight | Apertura/chiusura del driver alle estremità |
| Canale e autorizzazione separati | Rendere revisionabile il confine di sicurezza | Test mirati senza simulare TLS in produzione |
| Enum wire con nomi invariati | Evitare stringhe magiche preservando interoperabilità | Versione 0 invariata e test di compatibilità |
| UI composta in sezioni | Rendere modificabili layout e interazioni locali | Nessuna nuova libreria di navigazione o DI |

Le decisioni successive che cambiano sicurezza, dipendenze, schema o ciclo di vita saranno registrate qui oppure in un ADR separato se richiedono alternative e trade-off più ampi.

Incremento successivo: [ADR 001 — identità Mac](docs/ADR-001-IDENTITA-MAC.md). Adattatore KeychainStore separato dalla migrazione e dal motore; riferimento locale con pin, importazione conservativa, verifica della chiave dopo rilettura, nessuna rotazione automatica in caso di errore. Dipendenze e protocollo invariati. Test portabili distinti dalla prova nativa Mac ancora non eseguita.

## 10. Revisione applicata al codice esistente

Incremento iOS: [ADR 002](docs/ADR-002-IDENTITA-IOS.md). Certificati affidati alla libreria Apple, accesso Keychain isolato, errore esplicito su persistenza incoerente, inizializzazione fuori dal thread UI e test nativi separati dai test Kotlin. Il modulo non replica il protocollo di rete.

| Problema riscontrato | Intervento eseguito | Evidenza |
|---|---|---|
| Android compilava sorgenti privati di connectivity | Varianti KMP JVM/Android e dipendenza Gradle ordinaria | Build APK riuscita; nessun `srcDir` verso un altro modulo |
| Il motore dipendeva dalla classe SQLite concreta | Contratti `DeviceRepository`, `MessageRepository`, `TrustRepository`; SQL nel modulo persistence | Test SQLite e integrazione TLS reali |
| Node conteneva il protocollo di ogni socket | Estratti `PeerConnection`, `FrameStream` e `PairingAuthorization` | Test integrazione e due test framing |
| Candidato/scadenza erano variabili separate con tempo di calendario | Stato sincronizzato, tempo monotono e token per tentativo | Tre test di autorizzazione, incluso tentativo obsoleto |
| Callback della vecchia attivazione potevano aggiornare quella nuova | Risorse e callback vincolati a un `ServiceRun`; analoga separazione in Android NSD | Test callback dopo arresto/riavvio; Android NSD compilato ma non eseguito su telefono |
| Tipi messaggio e limiti ripetuti | `FrameType`, validazione centralizzata, `ContentLimits` | JSON e byte firmati compatibili con v0; limiti UTF-8 testati |
| Deduplicazione separata dall'inserimento | Controllo/insert nella stessa transazione SQLDelight | Duplicato idempotente e conflitto rifiutato senza perdere il dato originale |
| Chiusura risorse desktop ripetuta in più rami | Ownership annidata con `use`, uscita Compose senza terminazione anticipata del processo | Compilazione e distributable Windows; interazione grafica non provata |
| Composable monolitico | Sezioni per impostazioni, pairing, peer, composizione testo e cronologia | Build Compose JVM e Android |
| Documentazione e CI riferite al vecchio modulo JVM | Task `jvmTest`, README, stato e contratto aggiornati | Comando completo riuscito senza aggiornare i lock |

Esito: 18 test superati, pacchetto Windows con runtime e APK Android generati; lint Android con zero errori e 18 warning mantenuti visibili. Lock desktop Mac ARM64, Mac x64 e Linux x64 risolti senza modificarli. Non sono build su quei sistemi.

Rimangono da affrontare, prima delle rispettive funzionalità: operazioni sincrone negli ingressi UI, errori di servizio ancora presentati come testo anziché modello localizzabile completo, completamento atomico/distribuito dell'associazione, iOS autenticato e keystore desktop. Non sono stati introdotti finti adattatori per nascondere questi punti. `.editorconfig` orienta gli editor; non equivale a un formatter o a un controllo statico automatizzato in CI.
