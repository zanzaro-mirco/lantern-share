# Piano di sviluppo — App Kotlin Multiplatform per condivisione locale

## 1. Obiettivo e piattaforme

Realizzare un’app per condividere testo, immagini e file tra dispositivi nella stessa rete locale, anche senza Internet.

**La prima versione completa includerà un’applicazione dedicata per Mac**, oltre alle versioni Android, iPhone, Windows e Linux.

| Piattaforma | Supporto iniziale |
|---|---|
| Android | Android 10 e successivi |
| iPhone | iOS 16 e successivi |
| **Mac** | **macOS 13 e successivi, sia Apple Silicon sia Intel** |
| Windows | Windows 11, x64 |
| Linux | Ubuntu 24.04 LTS, x64 |

L’app Mac sarà installabile e utilizzabile autonomamente, con pacchetti per le due architetture, integrazione nella barra dei menu e funzionamento in background mentre il computer è acceso e operativo.

Il prodotto è destinato a piccoli gruppi di circa 2–10 dispositivi. Non richiede account online, backend cloud o un computer sempre acceso.

### Esperienza principale

1. L’utente assegna un nome al dispositivo e abilita il servizio.
2. L’app rileva gli altri dispositivi raggiungibili.
3. Un membro autorizza l’ingresso di un nuovo dispositivo tramite QR o confronto di un codice.
4. Le connessioni successive avvengono automaticamente.
5. Gli utenti condividono contenuti nella chat locale o inviano file a un destinatario specifico.

### Gruppo e sessioni

- Ogni installazione appartiene a un solo gruppo e partecipa a una sola sessione attiva.
- L’autorizzazione al gruppo persiste quando cambia la rete.
- Ogni sessione ha un identificativo casuale, indipendente dal nome del Wi-Fi e dagli indirizzi IP.
- Al cambio di rete si interrompono i collegamenti precedenti e si cerca una sessione del gruppo nella nuova LAN; in assenza se ne crea una.
- La vecchia cronologia rimane consultabile senza essere ripubblicata.
- La sessione continua finché almeno un partecipante la mantiene attiva. Se tutti diventano offline, può iniziare una nuova sessione alla riattivazione.
- Due sessioni già utilizzate non vengono unite automaticamente: l’utente sceglie a quale partecipare. Sessioni vuote nate simultaneamente convergono automaticamente.

Sono supportati Wi-Fi ed Ethernet comunicanti nella stessa LAN. Isolamento dei client, firewall e segmentazione della rete possono impedire la comunicazione.

## 2. Funzionalità

### Dispositivi e autorizzazioni

- Scoperta automatica e riconnessione.
- Nome, sistema operativo e stato del dispositivo.
- Interruttore per attivare o arrestare il servizio.
- Associazione tramite QR o codice di confronto.
- Collegamento tramite indirizzo locale quando la scoperta automatica non funziona.
- Elenco dei dispositivi autorizzati e uscita dal gruppo.

Ogni membro può autorizzare nuovi ingressi. La prima versione non prevede ruoli amministrativi: l’esclusione definitiva di un membro dall’intero gruppo richiede la creazione di un nuovo gruppo. Un blocco locale interrompe soltanto i collegamenti con quel dispositivo.

### Chat locale

- Testo, link, immagini e allegati.
- Copia e incolla espliciti, senza monitoraggio continuo degli appunti.
- Cronologia locale con ricerca.
- Conferme di ricezione per dispositivo.
- Recupero dei messaggi persi da un partecipante online che ne conserva una copia.
- Nessuna distribuzione dei messaggi anteriori all’ammissione di un nuovo membro.

I destinatari sono i membri ammessi alla sessione al momento dell’invio. Chi è temporaneamente offline può recuperare il messaggio; chi entra successivamente non diventa destinatario retroattivamente.

La conferma “ricevuto” indica che il contenuto è stato salvato sul dispositivo, non che sia stato letto.

### File e immagini

- Invio di uno o più file a un dispositivo oppure pubblicazione nella chat.
- Accettazione esplicita dei file e download su richiesta.
- Avanzamento, velocità, annullamento e ripresa.
- Verifica dell’integrità prima di dichiarare il completamento.
- Controllo dello spazio disponibile e gestione dei nomi duplicati.
- Supporto a file superiori a 4 GB senza caricarli interamente in memoria.

La ripresa di un invio diretto richiede il ritorno del mittente. Gli allegati della chat possono essere recuperati anche da altri membri autorizzati che ne conservano una copia completa.

### Interfaccia e integrazioni

Tre aree principali: **Chat**, **Dispositivi**, **Trasferimenti**.

| Piattaforma | Integrazioni |
|---|---|
| **Mac** | **Trascinamento dal Finder, copia/incolla, selezione e salvataggio file, notifiche, icona nella barra dei menu, avvio al login opzionale** |
| Windows e Linux | Trascinamento, scorciatoie, notifiche e area di notifica dove disponibile |
| Android | Menu di condivisione, notifiche e servizio attivato dall’utente |
| iOS | Selezione file/foto e Share Extension per preparare contenuti da inviare nell’app |

L’interfaccia sarà adattiva, con tema chiaro/scuro e accessibilità essenziale.

### Background e conservazione

- **Mac, Windows e Linux:** servizio attivo anche con finestra chiusa, finché l’app resta in esecuzione; nessuna promessa di ricezione durante la sospensione del computer.
- Android: foreground service con notifica persistente, nel rispetto dei vincoli del sistema.
- iOS: riconnessione e recupero alla riapertura, senza promessa di disponibilità continua in background. [Limiti Apple](https://developer.apple.com/forums/thread/685525)

Default:

- Cronologia di 30 giorni, configurabile anche senza scadenza.
- Cache allegati di 1 GB, configurabile.
- File salvati dall’utente esclusi dalla pulizia.
- Cancellazione della cronologia solo locale.
- Nessuna pulizia dei file coinvolti in trasferimenti attivi.

Restano fuori dalla prima versione: cartelle, sincronizzazione automatica degli appunti, chat private, più canali, browser e condivisione via Internet.

## 3. Architettura e contratti tecnici

### Responsabilità tecnica e qualità del codice

L'assistente di sviluppo opera nel ruolo di **sviluppatore Kotlin/Kotlin Multiplatform e software architect senior**: cura sia l'implementazione sia la coerenza dell'architettura, motivando le decisioni e verificandone gli effetti. Questo ruolo definisce responsabilità operative e standard di lavoro.

Il codice deve essere pulito, leggibile, testabile e mantenibile. Sono richiesti:

- responsabilità riconoscibili per modulo e componente, dipendenze esplicite e nessun accesso ai sorgenti interni di un altro modulo;
- regole di dominio e protocollo indipendenti da UI, database e API di piattaforma; adattatori alle estremità e composizione negli ingressi delle app;
- nomi espressivi, tipi per gli stati e i messaggi, invarianti centralizzate e funzioni focalizzate; astrazioni introdotte solo per responsabilità o variabilità reali;
- stato immutabile esposto alla UI, proprietà e durata delle risorse documentate, concorrenza e cancellazione gestite esplicitamente;
- sicurezza verificabile, errori osservabili senza divulgare contenuti o chiavi, persistenza coerente e compatibilità dei dati/protocolli preservata durante i refactoring;
- test dei comportamenti e delle condizioni di errore, build dei target disponibili e dichiarazione separata delle verifiche non eseguite;
- revisione del codice a ogni incremento, decisioni e debito tecnico documentati, niente framework aggiuntivi o livelli architetturali senza necessità dimostrata.

Il metodo operativo, i criteri di revisione e la definizione di completamento sono descritti in [ARCHITETTURA_E_QUALITA.md](ARCHITETTURA_E_QUALITA.md). I refactoring non modificano i requisiti di prodotto né i criteri di accettazione. La fase 0 è chiusa sul percorso fisico Android ↔ Windows; i collaudi residui di tale percorso e quelli su iPhone e Mac Intel/Apple Silicon appartengono alla fase 1.

### Tecnologia e moduli

Utilizzare Kotlin Multiplatform per la logica e Compose Multiplatform per l’interfaccia, con adattatori specifici per sistema operativo. La versione Mac utilizzerà il target desktop JVM, con runtime incluso nella distribuzione.

Moduli:

- **Dominio:** dispositivi, gruppi, sessioni, messaggi e trasferimenti.
- **Protocollo:** serializzazione, compatibilità, sincronizzazione e deduplicazione.
- **Connettività:** scoperta, collegamenti e riconnessione.
- **Persistenza:** database, code e trasferimenti parziali.
- **Interfaccia:** schermate e stato UI.
- **Piattaforme:** rete, file, appunti, notifiche, chiavi e ciclo di vita.

Utilizzare coroutines e `Flow`, SQLite tramite SQLDelight e filesystem per gli allegati. Bloccare le versioni compatibili delle dipendenze al termine della prova tecnica iniziale.

### Scoperta e trasporto

Adottare mDNS/DNS-SD:

- Android: `NsdManager`.
- iOS: Bonjour tramite Network framework.
- Mac, Windows e Linux: JmDNS sul runtime JVM.

Utilizzare collegamenti diretti tra partecipanti, senza server centrale:

- Una connessione di controllo per coppia di dispositivi.
- Connessioni separate per i file.
- Riconnessione con attese progressive e casualizzazione.
- Una sola interfaccia LAN attiva.
- Nessun inoltro tra reti e nessuna scansione continua della sottorete.

Trasporto TCP con TLS:

- Android e desktop, incluso Mac: API TLS JVM.
- iOS: `NWConnection` e `NWListener`.

### Identità e sicurezza

Ogni installazione possiede un’identità crittografica persistente.

- L’associazione verifica l’identità tramite QR o confronto esplicito di un codice derivato dall’handshake.
- Le riconnessioni verificano l’identità autorizzata.
- L’ammissione produce una credenziale firmata da un membro autorizzato.
- Le chiavi sono protette tramite strumenti del sistema operativo, incluso il **Portachiavi di macOS**.
- Una reinstallazione che perde le chiavi richiede una nuova autorizzazione.
- I messaggi sono firmati per verificarne l’origine anche durante il recupero da altri membri.

Usare primitive crittografiche consolidate; non accettare indiscriminatamente certificati autofirmati. La protezione del trasporto non impedisce ai destinatari autorizzati di copiare i contenuti ricevuti.

### Interfacce e dati

Contratti condivisi:

| Interfaccia | Responsabilità |
|---|---|
| `DiscoveryService` | Pubblicazione e ricerca |
| `PeerTransport` | Connessioni autenticate e frame |
| `IdentityStore` | Identità e credenziali |
| `SessionRepository` | Gruppi, sessioni e ammissioni |
| `MessageRepository` | Messaggi, ricevute e recupero |
| `TransferManager` | Offerte, trasferimenti e verifica |
| `PlatformServices` | Integrazioni native |

Entità principali: `DeviceIdentity`, `GroupMembership`, `Session`, `Message`, `Receipt`, `Attachment`, `Transfer`.

Il protocollo v1 comprende versione, ID evento, mittente, sessione, negoziazione delle funzionalità, presenza, ammissione, messaggi, ricevute, sincronizzazione e trasferimenti. Metadati serializzati con `kotlinx.serialization`, file trasmessi come blocchi binari.

### Affidabilità

- ID univoci e scritture idempotenti.
- Contatori per autore e ordinamento logico deterministico.
- Recupero degli intervalli mancanti, inclusi eventuali buchi.
- Ricevute solo dopo la persistenza.
- Autorizzazioni verificate anche durante recupero e download.
- Trasferimenti a blocchi con stato persistente e hash finale.
- Invalidazione della ripresa se cambia il file sorgente.

La diagnostica distingue permessi negati, scoperta indisponibile, peer irraggiungibile, autenticazione fallita e incompatibilità. I log escludono contenuti e chiavi.

## 4. Roadmap e distribuzione

Stime per uno sviluppatore esperto in Kotlin, quasi a tempo pieno, con supporto AI.

| Fase | Risultato verificabile | Stima |
|---|---|---:|
| 0. Prova tecnica | Android e Windows reali si scoprono, si autenticano e comunicano tramite il canale cifrato sulla LAN | 2–3 settimane |
| 1. Fondamenta e validazione multipiattaforma | Progetto KMP, CI, persistenza, identità e protocollo v1; percorso Apple completo; collaudi residui Android ↔ Windows e collaudi fisici su iPhone e Mac Intel/Apple Silicon, inclusa la LAN senza Internet | 2–3 settimane |
| 2. Rete e gruppo | Associazione, sessioni, riconnessione e collegamento manuale | 3–4 settimane |
| 3. Chat | Testo, ricevute, cronologia, ricerca e recupero | 3–4 settimane |
| 4. Contenuti | Immagini, file, ripresa e integrità | 3–5 settimane |
| 5. Integrazioni | Background, notifiche, condivisione e UX sulle cinque piattaforme | 3–5 settimane |
| 6. Beta e rilascio | Collaudo, installer, firme e documentazione | 3–5 settimane |

Totale indicativo: **19–29 settimane**, più un margine del 20–30%.

La prova iniziale ha validato il percorso verticale su Android e Windows reali. La fase 1 deve completare le verifiche residue Android ↔ Windows e validare iOS e Mac su hardware reale prima dello sviluppo completo dell’interfaccia. Windows e Linux vengono verificati a ogni traguardo successivo.

### Metodo di esecuzione — aggiornamento del 18 ottobre 2026

L'unità di consegna è un **blocco funzionale circoscritto**, non una singola classe, facciata o piattaforma. Questa organizzazione sostituisce la frammentazione in consegne tecniche indipendenti: non modifica requisiti, fasi, contratti di sicurezza o criteri di collaudo. Le stime sopra restano indicative, non una previsione aggiornata né una promessa di accelerazione misurata.

Prima di iniziare un blocco, definire in forma breve:

- risultato osservabile e percorso reale che lo utilizzerà;
- criteri di accettazione, compresi errori, cancellazione e riapertura quando pertinenti;
- componenti e piattaforme coinvolti, esclusioni e dipendenze ancora aperte;
- controlli locali e checkpoint remoti necessari a dimostrarlo.

Mantenere un solo blocco attivo. All'interno procedere per piccoli passi compilabili, completando core condiviso, adattatori necessari e relativa integrazione senza chiedere conferma dopo ogni passaggio tecnico. Un prerequisito infrastrutturale può essere consegnato separatamente se necessario per rischio o verificabilità, ma deve avere un utilizzatore e un criterio d'integrazione espliciti: non equivale a una funzionalità di prodotto completata. Non estendere il blocco all'intera roadmap. Fermarsi per decisioni di prodotto non definite, incompatibilità di dati/protocollo, nuove autorizzazioni o blocchi effettivi; inviare aggiornamenti di avanzamento senza trasformarli in richieste di conferma.

#### Verifiche e consegna

1. Durante l'implementazione eseguire i test mirati delle regole e dei confini modificati; ripeterli solo dopo cambiamenti pertinenti o errori.
2. Alla chiusura eseguire una verifica integrata sui target interessati e rivedere concorrenza, ownership, autorizzazioni, errori e persistenza. Un guasto nel codice interessato va corretto prima di ampliare il lavoro.
3. Conservare le regressioni importanti nei test versionati ed eseguibili dal repository. Gli harness locali ignorati servono all'esplorazione, non sostituiscono evidenze riproducibili; test comuni per le regole condivise, test OS per adattatori e lifecycle, integrazioni reali per crittografia/rete/SQLite.
4. Raggruppare le modifiche coerenti e fare un push al checkpoint del blocco, non uno per ogni strato. Riutilizzare la selezione CI per percorsi già presente. Non sopprimere controlli necessari per ridurre i tempi.
5. Usare il checkpoint Apple completo quando occorre verificare runtime Native/simulatore di un'integrazione significativa. Evitare run ordinarie e complete duplicate sullo stesso checkpoint; se indispensabile un controllo intermedio di export/compilazione, dichiararne lo scopo senza chiamarlo runtime verificato. Nessuna modifica implicita ai workflow: eventuali interventi richiedono una modifica dedicata con test della selezione CI.
6. Nessun polling o attesa della CI: leggere una run conclusa alla ripresa e recuperare una sola volta i link dopo il push. Se pendente, riportare commit/link e fermarsi, senza dichiarare il blocco verificato da remoto. Non lanciare build per sole modifiche documentali.

#### Coda operativa immediata

Questi blocchi ordinano il lavoro già previsto, non sostituiscono le fasi della roadmap. Un solo blocco è attivo; il successivo inizia dopo la chiusura o l'esplicitazione del vincolo residuo del precedente. B1/B2 e lettura dell'appartenenza B3 verificati automaticamente: ultimo checkpoint iOS completo `dc33c26` / 39167348683, Native/export/app e 156 XCTest riusciti, non hardware. Politica A di [ADR 012](docs/ADR-012-COMMIT-E-INTERRUZIONI-AMMISSIONE.md) confermata dall'utente: commit locale atomico, nuovo confronto prima di riprovare un'interruzione pre-commit, gruppo conservato dopo commit. B3 attivo: ingresso fondatore→nuovo membro nel Node Android/desktop (`a4613c1`, CI PoC/iOS ordinaria riuscite, quest'ultima solo compilazione) e nuovo ingresso BonjourProbe/UI iPhone implementato, ancora da verificare in Apple. Stato/evidenze correnti in STATO. Dopo checkpoint Apple concluso/correzioni, prossimo blocco unico: produttore verificato della prova delegata e percorso del membro emittente, perché ogni membro deve autorizzare. Il percorso temporaneamente limitato al fondatore non introduce amministratori né riduce la specifica. Nessun protocollo distribuito nuovo, sessione o traffico di gruppo attivato.

| Blocco | Risultato e accettazione | Confini e verifica |
|---|---|---|
| B1 — completare l'integrazione dell'handover Apple | Il confronto vivo passa alla continuazione nello stesso owner Swift con certificati degli endpoint TLS effettivi; callback pendenti gestiti, deadline originale e revoche preservate, nessun consenso ripristinato dal journal | Riusa core e facciate esistenti; integrazione TLS/lifecycle e checkpoint Apple, inclusi i test della facciata ancora da eseguire. Non comprende commit, recovery o UI. È un prerequisito tecnico, non un'ammissione completa utilizzabile |
| B2 — adozione durevole e interruzioni | Completare il percorso integrato di ammissione previsto dalla specifica, con persistenza coerente, retry idempotente e comportamento definito in caso di arresto, riapertura o revoca; nessuna autorizzazione ricavata dalla sola verifica storica | Prima esplicitare nel relativo ADR le garanzie e i punti di commit mancanti; implementare insieme contratti, persistenza, orchestrazione e adattatori necessari, non altre API isolate. Test con TLS/firme/SQLite reali e interruzioni ai punti critici. Decisione esplicita se serve incompatibilità wire/schema; nessun nuovo protocollo distribuito assunto come già approvato |
| B3 — percorso di gruppo nel servizio e nell'interfaccia | Collegare l'ammissione verificata agli ingressi dell'app e presentare stati, errori e appartenenza persistente; provarne uso e riapertura, non soltanto compilazione delle API | Riutilizzare l'orchestrazione del blocco precedente. Lo sviluppo completo della UI resta subordinato ai collaudi fisici di fase 1. Sessioni, riconnessione e collegamento manuale seguono come blocchi funzionali della fase 2, non come estensione automatica di B3 |

I collaudi fisici restano una lista di accettazione aperta: residui Android ↔ Windows (incluse WAN disattivata, bidirezionalità, riavvio e regressione del blocco locale), iPhone e Mac Intel/Apple Silicon. L'assenza dell'hardware non impedisce il lavoro tecnico indipendente, ma non chiude la fase 1 né rimuove il vincolo sullo sviluppo completo della UI. Non ricominciare identità, SQLite o comunicazione già verificate.

#### Stato e documentazione

Misurare l'avanzamento per capacità utilizzabili e criteri di accettazione soddisfatti, non per numero di commit, classi, test o build. Distinguere sempre: prerequisito tecnico, integrazione nell'app, compilato, testato automaticamente, verificato su hardware.

Mantenere breve la sezione corrente di `STATO_SVILUPPO.md`: capacità disponibile, evidenze con commit/comandi/link, limiti e un solo blocco successivo. `PASSAGGIO_CONSEGNE.md` contiene solo istruzioni di ripartenza e riferimenti alle evidenze; gli ADR ospitano le decisioni, senza ricopiarle in entrambi i file. Non aggiungere nuovi resoconti storici duplicati: quando si separa lo storico esistente, archiviarlo con link e senza perdere evidenze. La riorganizzazione documentale non deve diventare un prerequisito continuo allo sviluppo.

### Consegna specifica per Mac

- Applicazione `.app` con runtime incluso.
- Distribuzione tramite `.dmg`, con pacchetti distinti Apple Silicon e Intel.
- Firma Developer ID e notarizzazione per la distribuzione esterna al Mac App Store.
- Verifica dell’installazione su un Mac privo degli strumenti di sviluppo.
- Gestione dei permessi di rete locale richiesti dal sistema.
- Conservazione di identità e database durante gli aggiornamenti.
- Documentazione per installazione, avvio al login e disinstallazione.

Il Mac App Store non è incluso nella prima distribuzione.

Servono un Mac con Xcode, un iPhone e un Android reali, oltre a dispositivi o ambienti di test Windows/Linux. Il collaudo Mac deve coprire entrambe le architetture.

## 5. Collaudo e criteri di completamento

La fase 0 è completata dal percorso reale Android ↔ Windows con scoperta, autenticazione e comunicazione sul canale TLS. La fase 1 comprende la ripetizione con WAN disattivata, il testo in entrambe le direzioni, il riavvio dei processi e tutti i collaudi fisici che coinvolgono iPhone o Mac, comprese entrambe le architetture Mac. Queste verifiche restano obbligatorie; la matrice completa delle piattaforme rimane un criterio della prima versione e della beta.

### Verifiche automatiche

- Deduplicazione, ordinamento e recupero.
- Esclusione della cronologia precedente all’ammissione.
- Credenziali alterate e identità sconosciute.
- Riconnessioni simultanee e collegamenti duplicati.
- Trasferimenti interrotti o corrotti.
- Migrazioni e arresti improvvisi.
- Frame malformati, limiti e destinazioni file non autorizzate.

### Verifiche reali

Provare tutte le dieci coppie tra piattaforme, in entrambe le direzioni, e dispositivi con lo stesso sistema operativo.

In particolare: **Mac ↔ Android, Mac ↔ iPhone, Mac ↔ Windows, Mac ↔ Linux e Mac ↔ Mac Intel/Apple Silicon**.

Scenari:

- LAN senza Internet, Wi-Fi ed Ethernet.
- IPv4, IPv6 e dual stack.
- Multicast bloccato, firewall e isolamento client.
- Cambio rete/IP e reti con lo stesso nome Wi-Fi.
- Sospensione e riattivazione del Mac.
- Android in risparmio energetico e iPhone bloccato.
- Disco pieno, nomi duplicati, Unicode e file oltre 4 GB.
- Dieci dispositivi con chat e trasferimenti concorrenti.

### Criteri di accettazione

Su una LAN di prova senza isolamento:

- Connessione automatica entro 10 secondi nel 95% delle prove.
- Messaggi brevi ricevuti entro un secondo nel 95% delle prove con collegamenti attivi.
- Nessun duplicato dopo riconnessione.
- Nessuna cronologia anteriore all’ammissione.
- Ripresa dei file senza ricominciare dall’inizio.
- Integrità verificata per ogni trasferimento completato.
- Memoria limitata dai buffer, indipendentemente dalla dimensione del file.
- Continuità tra gli altri partecipanti quando il primo dispositivo lascia la sessione.
- Arresto del servizio che interrompe annunci e comunicazioni.
- Recupero su iOS alla riapertura quando i contenuti sono disponibili.
- **Installazione e funzionamento della versione Mac su Intel e Apple Silicon senza Java installato separatamente.**

La release completa segue una beta con un piccolo gruppo, il superamento della matrice di test e la verifica del protocollo di associazione.
