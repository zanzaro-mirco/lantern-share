# Selezione della sessione LAN

Prima regola di dominio per gruppi/sessioni del piano, implementata in `domain/SessionSelection.kt`. Non è ancora collegata al servizio wire 0 e non definisce un nuovo formato di rete o schema SQLite.

`SessionSelector.select` riceve il gruppo dell'installazione e uno snapshot di sessioni attive della LAN corrente, inclusa quella locale se attiva. Le offerte di altri gruppi sono escluse. Gli ID sono opachi, non vuoti, non normalizzati: non derivano da SSID, IP o nome dispositivo. Generazione casuale e autenticazione delle offerte saranno responsabilità dei futuri adattatori.

| Snapshot del gruppo | Decisione |
|---|---|
| Nessuna sessione attiva | `Create`: generare un ID casuale nuovo |
| Solo sessioni vuote | `Join`: ID lessicograficamente minimo, indipendente dall'ordine degli annunci |
| Una sola sessione utilizzata, eventualmente con sessioni vuote | `Join`: sessione utilizzata |
| Più sessioni utilizzate | `Choose`: scelta esplicita, nessuna fusione automatica |

Annunci identici della stessa sessione sono deduplicati; osservazioni contraddittorie sono rifiutate, non risolte per ordine di arrivo. Il futuro proprietario dello snapshot dovrà gestire aggiornamenti/scadenze prima di chiamare la regola. Il flag `used` è monotono per una sessione: cancellare la cronologia locale non rende nuovamente vuota una sessione utilizzata.

Il selettore non conosce archivi o messaggi: non ripubblica né unisce cronologie. La cronologia precedente non deve essere inserita nello snapshot, né riattivata quando tutti i partecipanti sono offline. `Join` è una decisione di selezione, **non una credenziale di ammissione**: trasporto, appartenenza, autorizzazioni e destinatari devono essere verificati separatamente prima di comunicare.

Verifica locale: `./gradlew -Pandroid=true :domain:jvmTest :domain:testDebugUnitTest --console=plain`, otto casi condivisi per target. Coprono creazione, separazione gruppi, convergenza indipendente dall'ordine, priorità della sessione utilizzata, scelta esplicita, duplicati, conflitti e ID vuoti. Non equivalgono a convergenza distribuita su rete o a collaudo hardware. I test Native sono inclusi nel checkpoint iOS manuale, non eseguiti localmente su Windows.

Restano da implementare credenziali di gruppo, snapshot autenticato e ciclo di vita/cambio rete, persistenza e UI della scelta. Nessuna autorizzazione derivata da mDNS o da `READY` del bootstrap.
