# Piano di collaudo reale — fase 0 completata, fase 1 in corso

## Preparazione

La fase 0 è stata completata con Android 10+ e Windows 11 reali. La fase 1 completa su questa coppia le prove con WAN disattivata, bidirezionalità e riavvio, e aggiunge iPhone iOS 16+ e Mac macOS 13+ sia Apple Silicon sia Intel; Ubuntu 24.04 e le altre coppie seguono la matrice di prodotto. Annotare OS, architettura, commit/hash delle sorgenti, JDK, build, IP e interfaccia selezionata. Non riutilizzare identità copiate tra dispositivi.

Router/AP con rete LAN isolata da Internet, client isolation disabilitato. Testare Wi-Fi/Wi-Fi e Wi-Fi/Ethernet. Disattivare la WAN dopo installazione e prima delle prove. Consentire rete locale all'app, non disabilitare globalmente il firewall.

**Blocco della fase 1:** iOS implementa identità Keychain e sonda Bonjour, ma non trasporto e associazione. Le prove 3–10 relative a iPhone non sono ancora eseguibili; richiedono il collegamento autenticato completo. Non compilare “superato” per tali celle.

Prova parziale iPhone già predisposta: annotare l'ID mostrato, terminare completamente il processo e riaprire; l'ID deve restare uguale. Verificare che un errore Keychain blocchi la scoperta e non sia sostituito da una nuova identità. Il blocco/sblocco del dispositivo e la conservazione dei dati dopo aggiornamento richiedono dispositivo fisico; i test del simulatore non li certificano.

## Sequenza per ciascuna coppia

1. Installare build locali autorizzate. Su Mac usare `.app` con runtime incluso, anche su host senza Java. Verificare separatamente Intel e Apple Silicon.
2. Avviare e assegnare nomi diversi. Attivare il servizio; misurare la scoperta con cronometro. Per iPhone usare per ora “Cerca nella LAN”. Annotare eventuale prompt rete locale negato/concesso.
3. Tentare connessione senza selezione reciproca: nessun testo deve passare. Nomi uguali non devono conferire trust.
4. Selezionare i candidati su entrambi; confrontare tutto il codice. Rifiutare una volta: niente persistenza dell'autorizzazione. Riprovare e confermare su entrambi.
5. Inviare testo ASCII e Unicode in entrambe le direzioni; attendere ricevuta. Riavviare processo e verificare identità invariata, cronologia presente, riconnessione automatica e assenza di duplicati.
6. Bloccare localmente un peer e provare a inviare: nessuna nuova ricezione. Una nuova identità con stesso nome deve richiedere associazione.
7. Catturare il traffico sul proprio laboratorio (Wireshark): TLS 1.3, testo non leggibile, nessun contenuto applicativo prima della conferma. Conservare solo catture con dati di prova.
8. Arrestare il servizio: listener chiuso, socket chiusi, annuncio ritirato. Riattivare e verificare riconnessione. Ripetere almeno 20 volte.
9. Sospendere/riattivare Mac, bloccare iPhone, passare Android in background. Confrontare con comportamento effettivamente supportato, senza promettere background su iOS. Registrare le lacune, non marcarle conformi.
10. Cambiare rete/IP; testare multicast bloccato, IPv6, dual stack e isolamento client. Il PoC desktop seleziona IPv4 e richiede riavvio al cambio rete: IPv6 e recupero automatico restano non conformi.

Per l'obiettivo del piano (<10 s nel 95% delle connessioni, <1 s nel 95% dei messaggi attivi), raccogliere almeno 100 misure per scenario/coppia e calcolare percentili; nessuna stima dalla sola impressione visiva.

## Registro da compilare

### Portachiavi Mac — nuovo incremento, non collaudato

Ripetere su Intel e Apple Silicon, con profili di prova e `.app` con runtime incluso:

1. Nuovo profilo: verificare elemento `lantern-…` in Accesso Portachiavi, `mac-identity.ref` sul disco e assenza di nuovo `identity.p12`. Annotare ID, chiudere completamente il processo, riaprire e verificare lo stesso ID.
2. Profilo PKCS#12 precedente: associare prima un peer, conservare copia cifrata di prova, migrare con la passphrase. ID, cronologia e riconnessione senza nuova associazione devono rimanere invariati; il backup deve essere identico byte per byte.
3. Annullare o sbagliare la passphrase: nessuna nuova identità e nessuna apertura della rete. Ripetere con Portachiavi bloccato e accesso negato; verificare errore senza ripiego su PKCS#12.
4. Solo su profilo sacrificabile, rimuovere l'elemento Portachiavi: senza backup l'app deve fermarsi; con backup originale può reimportare solo lo stesso certificato. Provare riferimento corrotto e backup di un'altra identità: avvio rifiutato.
5. Verificare i prompt anche dopo un aggiornamento del pacchetto. Annotare eventuali differenze fra JDK di sviluppo e runtime incluso. Non considerare una firma Java riuscita prova di chiave non esportabile.

La prova automatica nativa richiede un account/Portachiavi usa e getta, `LANTERN_DISPOSABLE_KEYCHAIN=true` e `bash ./gradlew -PmacKeychain=true :connectivity:jvmTest --tests '*MacKeychainNativeTest'`. Il workflow prepara tale ambiente sui runner temporanei; non eseguire questa prova sul Portachiavi personale. Le prove JVM Windows simulano esclusivamente questo confine OS.

| Coppia | Scoperta | Associazione/TLS | Testo bidirezionale | Riavvio | Esito/data/evidenza |
|---|---|---|---|---|---|
| Mac ARM ↔ Android | non provato | non provato | non provato | non provato | |
| Mac Intel ↔ Android | non provato | non provato | non provato | non provato | |
| Mac ARM ↔ iPhone | non provato | non implementato iOS | non implementato iOS | non provato | |
| Mac Intel ↔ iPhone | non provato | non implementato iOS | non implementato iOS | non provato | |
| Android ↔ iPhone | non provato | non implementato iOS | non implementato iOS | non provato | |
| Mac ARM ↔ Mac Intel | non provato | non provato | non provato | non provato | |
| Mac ↔ Windows | non provato | non provato | non provato | non provato | |
| Mac ↔ Linux | non provato | non provato | non provato | non provato | |
| Android ↔ Windows | riuscita 28/09/2026 | riuscita dopo correzione digest Keystore | comunicazione riuscita; direzioni non annotate | non provato | conferma utente su hardware, 28/09/2026; log disponibile per il guasto precedente |

Il percorso fisico Android ↔ Windows ha confermato scoperta, collegamento e comunicazione e chiude la fase 0. La ripetizione con WAN disattivata, la bidirezionalità esplicita e il riavvio passano alla fase 1 insieme alle righe che coinvolgono iPhone o Mac. Estendere poi il registro a tutte le dieci coppie, entrambe le direzioni e stesso sistema operativo come richiesto dalla prima versione. Il successo dei test loopback non compila alcuna cella di questo registro.
