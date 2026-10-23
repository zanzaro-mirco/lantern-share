# Selezione della sessione LAN

Regola di dominio per gruppi/sessioni del piano, implementata in `domain/SessionSelection.kt`. Il primo ingresso esplicito Node Android/desktop è descritto in [ADR 014](ADR-014-NEGOZIAZIONE-INIZIALE-SESSIONE.md): formato opzionale separato dal wire 0 e nessun nuovo schema SQLite. Non è la gestione completa delle sessioni o un'autorizzazione alla chat.

`SessionSelector.select` riceve il gruppo dell'installazione e uno snapshot di sessioni attive della LAN corrente, inclusa quella locale se attiva. Le offerte di altri gruppi sono escluse dalla regola pura; l'ingresso di rete rifiuta invece un'offerta con gruppo diverso. Gli ID di dominio sono opachi, non vuoti, non normalizzati: non derivano da SSID, IP o nome dispositivo. L'adattatore Node genera ID casuali a 256 bit e verifica l'appartenenza sullo stesso TLS prima dello scambio. Le proposte nuove sono fallback soltanto se nessuno mantiene una sessione, non un motivo per cambiare quella rimasta attiva.

| Snapshot del gruppo | Decisione |
|---|---|
| Nessuna sessione attiva | `Create`: generare un ID casuale nuovo |
| Solo sessioni vuote | `Join`: ID lessicograficamente minimo, indipendente dall'ordine degli annunci |
| Una sola sessione utilizzata, eventualmente con sessioni vuote | `Join`: sessione utilizzata |
| Più sessioni utilizzate | `Choose`: scelta esplicita, nessuna fusione automatica |

Annunci identici della stessa sessione sono deduplicati; osservazioni contraddittorie sono rifiutate, non risolte per ordine di arrivo. Il futuro proprietario dello snapshot dovrà gestire aggiornamenti/scadenze prima di chiamare la regola. Il flag `used` è monotono per una sessione: cancellare la cronologia locale non rende nuovamente vuota una sessione utilizzata.

Il selettore non conosce archivi o messaggi: non ripubblica né unisce cronologie. La cronologia precedente non deve essere inserita nello snapshot, né riattivata quando tutti i partecipanti sono offline. `Join` è una decisione di selezione, **non una credenziale di ammissione**: trasporto, appartenenza, autorizzazioni e destinatari devono essere verificati separatamente prima di comunicare.

Verifica locale: `./gradlew -Pandroid=true :domain:jvmTest :domain:testDebugUnitTest --console=plain`, otto casi condivisi per target. Coprono creazione, separazione gruppi, convergenza indipendente dall'ordine, priorità della sessione utilizzata, scelta esplicita, duplicati, conflitti e ID vuoti. Non equivalgono a convergenza distribuita su rete o a collaudo hardware. I test Native sono inclusi nel checkpoint iOS manuale, non eseguiti localmente su Windows.

Le credenziali di gruppo, B5 e il primo trasferimento di testo B6 sono verificati automaticamente anche iOS, ultimo completo fcec8f7 / 182 XCTest, non hardware. Nuovo roster Node/UI B7 in ADR 017: attestazioni firmate e memoria della run con offline, ingresso iOS ancora assente. Invio con snapshot multipartecipante, ciclo di vita/cambio rete automatico e scelta operativa restano aperti. La sola decisione B5 non autorizza traffico, né lo fanno mDNS/B4/READY bootstrap. SQLite conserva testo/used di ADR 015, non ripristina sessioni; il rientrante recupera da un peer attivo con nuove prove. Comandi e risultati correnti in STATO.

## Collaudo fisico B5 ancora da eseguire — Android ↔ Windows

Questa lista non è un'evidenza di collaudo riuscito. Usare build dello stesso
checkpoint e dispositivi di prova già ammessi allo stesso gruppo tramite il
confronto completo su entrambi. Non cancellare database/identità per riprovare.
I file e i messaggi della prova tecnica restano distinti dalla nuova negoziazione.

1. Attivare entrambi sulla stessa LAN, anche senza WAN, e selezionare **Negozia
   sessione** su entrambi. Attendere il risultato locale su ciascuno e confrontare
   gli ID completi: devono coincidere. Non aspettarsi chat di gruppo abilitata.
2. Chiudere i pannelli, lasciando i servizi attivi, e ripetere: stesso ID. Chiudere
   il pannello non equivale a uscire dal gruppo o arrestare il servizio.
3. Arrestare/riattivare soltanto un servizio, poi ripetere su entrambi: il rientrante
   raggiunge l'ID mantenuto dall'altro, anche se la sessione è ancora vuota.
4. Arrestare entrambi, riattivare e negoziare: nuovo ID comune, diverso da quello
   precedente. Gruppo e vecchia cronologia devono restare salvati; la cronologia
   non viene ripubblicata e il suo ID non viene usato come sessione corrente.
5. Annullare una negoziazione prima del risultato e riprovare con una nuova
   selezione su entrambi. Nessun callback precedente deve riaprire il pannello
   annullato. Provare anche stop e blocco locale durante la selezione.
6. Selezionare **Negozia sessione** da un lato e **Verifica membro** dall'altro:
   incompatibilità, nessuna autorizzazione o modifica del gruppo. Chiudere entrambi
   e riprovare nello stesso modo corretto. Non serve un nuovo invito.

Registrare commit/build, OS, rete/WAN, ordine delle azioni, esito per dispositivo
ed eventuale errore senza contenuti, credenziali o chiavi. Il cambio LAN automatico
non è implementato: arrestare il servizio prima di cambiare rete e riattivarlo
dopo. iPhone/Mac Intel/Apple Silicon restano nei collaudi obbligatori di fase 1;
l'ingresso B5 iOS è verificato automaticamente, non su hardware.
Applicare anche a iPhone la stessa lista con build dello stesso checkpoint,
registrando separatamente interoperabilità Apple ↔ Android/desktop.

## Collaudo fisico B6 ancora da eseguire — Android ↔ Windows e iPhone

Nuovo percorso di [ADR 016](ADR-016-PRIMO-TRASFERIMENTO-TESTO-GRUPPO.md), NON prova
già eseguita. Build dello stesso checkpoint, dispositivi già ammessi allo stesso
gruppo tramite il percorso di ingresso gruppo, non la sola associazione PoC.

1. Attivare entrambi sulla LAN; nel pannello **Testo di gruppo · primo trasferimento**
   digitare un testo e scegliere Invia verso l'altro dispositivo. Sul destinatario
   scegliere Ricevi dal mittente entro 120 s. Verificare testo e ID uguali e la
   conferma «Salvato sul destinatario» soltanto dopo il risultato.
2. Ripetere in direzione opposta senza fermare i servizi: stessa sessione, altro
   ID messaggio. La chiusura del pannello non azzera la sessione usata.
3. Arrestare entrambi e riattivare: nuovo ID sessione. Gruppo, identità e vecchie
   copie salvate non devono essere eliminate o ripubblicate. La UI completa della
   cronologia di gruppo non è ancora disponibile: non usare la lista PoC come
   evidenza della storia di gruppo; la riapertura dello storage è test automatico.
4. Provare due Invia, oppure Ricevi contro Negozia sessione: errore compatibilità,
   nessuna ricevuta falsa. Riprovare con ruoli corretti.
5. Annullare/fermare/bloccare durante il tentativo: nessuna conferma tardiva. Una
   copia locale può rimanere dopo un commit iniziato; non si ritrasmette da sola.
6. Dopo aver usato una sessione, fermare solo uno dei servizi, riattivarlo e
   negoziare B5. Il trasferimento può rifiutare lo scope perso con «roster
   autenticato richiesto»: limite attuale esplicito, NON errore da aggirare
   cancellando il database. Ripristino del roster e continuità completa restano aperti.

Ripetere senza WAN e registrare commit, OS, rete, ordine delle azioni, ID/esiti ed
eventuali errori senza contenuti o chiavi. Ingresso iPhone B6 verificato automaticamente
nel completo fcec8f7: applicare con build dello stesso checkpoint;
registrare separatamente Apple ↔ Android/desktop. iPhone/Mac e hardware di fase 1
rimangono obbligatori. Nessun collaudo nuovo attestato da questa lista.

## Collaudo fisico B7 predisposto, NON eseguito — roster Android/desktop

Nuova azione di [ADR 017](ADR-017-ROSTER-AUTENTICATO-SESSIONE.md), non chat completa.
Build dello stesso checkpoint e gruppo già ammesso, nessuna cancellazione DB.

1. Scegliere **Sincronizza roster** su A e B. Stesso ID sessione ed elenco di due
   fingerprint; non è lo stato online o una ricevuta. Chiudere i pannelli senza
   fermare i servizi e ripetere: stessa sessione.
2. Usare il testo iniziale, fermare/riaprire B lasciando A attivo, sincronizzare
   di nuovo: stesso ID e partecipanti, poi testo nuovamente possibile. Nessuna
   ripubblicazione della storia o ricevuta dedotta dalla sola sincronizzazione.
3. Con un terzo dispositivo C, dopo il primo roster A/B fermare il fondatore A,
   ammettere C tramite B e sincronizzare B/C: elenco di tre, incluso A offline.
   Fermare B, riaprire A e sincronizzare A/C: conservato anche B offline.
4. Con tre partecipanti il vecchio Invia/Ricevi testo deve rifiutare il roster,
   non mostrare un ACK o ridurlo ai due online. Invio multipartecipante ancora
   da integrare; C non diventa destinatario dei messaggi inviati prima del suo ingresso.
5. Provare Sincronizza contro Negozia sessione/testo, poi cancel e nuova selezione:
   incompatibilità o annullamento senza risultato tardivo; riprova esplicita corretta.
6. Se un partecipante legacy offline non ha mai firmato la propria presenza nel
   roster, il nuovo ingresso può richiederne le prove. Se nessuno conserva più lo
   snapshot di una sessione usata, rifiuto esplicito. Non aggirare con storia, reset
   used o cancellazione DB. Dopo stop di tutti, nuovo ID, copie vecchie preservate.

Ripetere senza WAN e registrare build/OS/rete/ordine/ID/esiti senza chiavi o contenuti.
Il terzo dispositivo è necessario al relativo collaudo, non simulato da questa lista.
Ingresso roster iOS ancora da realizzare; nessuna azione iPhone sostitutiva o test
fisico dichiarato. Cronologia gruppo UI completa e collaudi hardware restano aperti.
