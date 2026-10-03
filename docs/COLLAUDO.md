# Piano di collaudo reale — fase 0 completata, fase 1 in corso

## Preparazione

**Rinvio richiesto dall'utente il 3 ottobre 2026:** eseguire più avanti i collaudi fisici residui, senza considerarli superati. Restano da riprendere: Android ↔ Windows senza WAN, testi/ricevute bidirezionali e riavvio; regressione Android su blocco/rifiuto/arresto; iPhone ↔ Android/desktop; Mac Intel e Apple Silicon, inclusi Portachiavi, installazione e LAN senza Internet. Nessuna scadenza o automazione di monitoraggio impostata. Fase 1 aperta; si procede intanto con incrementi isolati del protocollo v1.

La fase 0 è stata completata con Android 10+ e Windows 11 reali. La fase 1 completa su questa coppia le prove con WAN disattivata, bidirezionalità e riavvio, e aggiunge iPhone iOS 16+ e Mac macOS 13+ sia Apple Silicon sia Intel; Ubuntu 24.04 e le altre coppie seguono la matrice di prodotto. Annotare OS, architettura, commit/hash delle sorgenti, JDK, build, IP e interfaccia selezionata. Non riutilizzare identità copiate tra dispositivi.

Router/AP con rete LAN isolata da Internet, client isolation disabilitato. Testare Wi-Fi/Wi-Fi e Wi-Fi/Ethernet. Disattivare la WAN dopo installazione e prima delle prove. Consentire rete locale all'app, non disabilitare globalmente il firewall.

**Stato della fase 1:** iOS implementa identità, SQLite, Bonjour, TLS, associazione e testo/ricevute; compilazione e test loopback simulatore riusciti sul commit `08dfb86` (19 XCTest). Questi risultati non verificano LAN, permessi o ciclo di vita su iPhone fisico. I collaudi Apple restano non provati, non più bloccati dall'assenza di messaggistica.

## Build di test e prima prova Android ↔ Windows

In GitHub aprire **Actions → Verify Lantern PoC → run riuscita del commit da provare → Artifacts**. Dalla modifica che introduce gli artefatti, scaricare `lantern-android-debug-test-<SHA>` e `lantern-windows-x64-test-<SHA>` della **stessa run**. Conservati per 14 giorni; non sono release o installer. Le run precedenti non contengono questi pacchetti.

- Android: estrarre lo ZIP e installare `androidApp-debug.apk` sul telefono di prova, oppure `adb install -r androidApp-debug.apk`. La chiave debug dei runner temporanei può differire da quella locale o da run precedenti: se Android rifiuta l'aggiornamento per firma diversa, fermarsi. Non disinstallare/cancellare dati automaticamente: si perdono cronologia e identità e occorre una nuova associazione. Per preservarle usare la build locale firmata dalla stessa chiave di quella già installata.
- Windows: estrarre **tutto** lo ZIP in una cartella distinta e avviare `Lantern.exe`, mantenendo insieme `app/` e `runtime/`. Java è incluso. Chiudere l'istanza precedente; non eliminare `%USERPROFILE%\.lantern`, che conserva identità e cronologia. Usare la passphrase esistente. Consentire la sola rete privata nel firewall, senza disabilitarlo.
- iPhone: l'artefatto `ios-verification` contiene risultati di test, **non un'app installabile**. Serve un Mac con Xcode, framework `iosArm64` e firma dispositivo configurata dal titolare; vedere README. Non trasferire al telefono una build del simulatore.

Prima prova circoscritta con Android e Windows disponibili:

1. Annotare SHA, versioni OS e ID completi dei due dispositivi. Installare prima di scollegare la WAN; lasciare attiva la LAN.
2. Attivare entrambi i servizi; se già associati, verificare il collegamento senza nuova conferma. Altrimenti associare e confrontare il codice intero su entrambi.
3. Inviare `Android → Windows: prova àè 漢字` e `Windows → Android: prova 🙂`. Verificare un solo inserimento per testo e ricevuta sul mittente, non soltanto comparsa sul destinatario.
4. Chiudere completamente entrambe le app, riaprirle e verificare ID, nomi, testi e ricevute invariati. Riattivare il servizio, controllare riconnessione senza nuova associazione e inviare un nuovo testo per direzione. I vecchi testi non devono duplicarsi.
5. Riprovare su Android “Arresta”, rifiuto di una nuova associazione e “Blocca localmente” senza crash. Il blocco deve impedire nuove ricezioni; per ripetere l'associazione occorre selezione e conferma reciproca, mai trust automatico.
6. Compilare una riga di evidenza con SHA, data, WAN disattivata sì/no, esito di ogni passo e log del solo errore eventuale. Non allegare database, passphrase, chiavi o testi personali. Un singolo giro non certifica i percentili richiesti dal prodotto.

Prova parziale iPhone già predisposta: annotare l'ID mostrato, terminare completamente il processo e riaprire; l'ID deve restare uguale. Verificare che un errore Keychain blocchi la scoperta e non sia sostituito da una nuova identità. Il blocco/sblocco del dispositivo e la conservazione dei dati dopo aggiornamento richiedono dispositivo fisico; i test del simulatore non li certificano.

## Sequenza per ciascuna coppia

1. Installare build locali autorizzate. Su Mac usare `.app` con runtime incluso, anche su host senza Java. Verificare separatamente Intel e Apple Silicon.
2. Avviare e assegnare nomi diversi. Attivare il servizio; misurare la scoperta con cronometro. Annotare eventuale prompt rete locale negato/concesso.
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
| Mac ARM ↔ iPhone | non provato | non provato | non provato | non provato | |
| Mac Intel ↔ iPhone | non provato | non provato | non provato | non provato | |
| Android ↔ iPhone | non provato | non provato | non provato | non provato | |
| Mac ARM ↔ Mac Intel | non provato | non provato | non provato | non provato | |
| Mac ↔ Windows | non provato | non provato | non provato | non provato | |
| Mac ↔ Linux | non provato | non provato | non provato | non provato | |
| Android ↔ Windows | riuscita 28/09/2026 | riuscita dopo correzione digest Keystore | comunicazione riuscita; direzioni non annotate | non provato | conferma utente su hardware; crash su blocco corretto, riprova fisica pendente |

Il percorso fisico Android ↔ Windows ha confermato scoperta, collegamento e comunicazione e chiude la fase 0. La ripetizione con WAN disattivata, la bidirezionalità esplicita e il riavvio passano alla fase 1 insieme alle righe che coinvolgono iPhone o Mac. Estendere poi il registro a tutte le dieci coppie, entrambe le direzioni e stesso sistema operativo come richiesto dalla prima versione. Il successo dei test loopback non compila alcuna cella di questo registro.
