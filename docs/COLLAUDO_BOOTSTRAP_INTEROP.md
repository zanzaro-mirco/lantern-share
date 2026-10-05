# Collaudo bootstrap JVM ↔ iOS (opt-in)

Aggiornamento 5 ottobre 2026. Test support in `connectivity/src/jvmTest`, `.github/scripts` e `iosApp/InteropTests`, **non app, servizio o protocollo applicativo**. Lato JVM validato localmente con un peer JVM reale; controller verificato su Windows. Percorso positivo JVM macOS ↔ iOS simulatore compilato/eseguito con successo in CI, non su hardware.

## Avvio e precondizioni

Il controller deve ottenere il pin pubblico dell'identità Apple di test e selezionarlo **prima di TLS**. Nessun pin da discovery, trust-all, chiave condivisa o conferma implicita. Il task usa JDK 17 e classpath jvmTest; non esporta `HandshakeV1Connection` né aggiunge dipendenze/versioni.

```text
./gradlew :connectivity:runHandshakeV1InteropFixture -PinteropPeerPin=PIN_APPLE_64_HEX --quiet --console=plain
```

Su Windows usare `gradlew.bat`. Sostituire il segnaposto con il pin minuscolo di 64 caratteri effettivamente selezionato. Il controller deve tenere stdin aperto, leggere stdout senza bloccare il processo e limitarne la durata complessiva; non avviare questa fixture come servizio persistente. Nel percorso positivo stderr/exit non zero indicano fallimento, mai successo parziale; il caso negativo sotto richiede invece un marker specifico ed exit 1 esatto. Il formato sotto è controllo del test, **non wire v1**, e non viene utilizzato dall'app.

## Controllo del test

1. stdout: `LISTENING 127.0.0.1 <port> <jvmPin>`. Identità JCA nuova in memoria; nessuna PKCS#12 o identità dell'utente. Il controller passa il pin JVM come selezione esplicita al trasporto Apple prima della connessione. Listener limitato a IPv4 loopback, TLS 1.3 reciproca, pin peer esatto, attesa accept/TLS limitata a 10 s.
2. Si scambiano HELLO attraverso i proprietari e i codec esistenti. stdout: `COMPARISON <sha256Completo>`. Il controller deve confrontarlo con il codice esposto dal proprietario Apple. Solo se coincidono, simulare le due conferme UI con il rispettivo ticket corrente. Nessuna decisione del protocollo viene spostata nel controller.
3. stdin: `CONFIRM <sha256Completo>` seguito da LF o CRLF. Il server firma e scrive APPROVE reale, attende/verifica la prova remota e richiede `READY` locale. Comando assente, troncato, non ASCII, troppo lungo o discordante termina senza concedere progresso; letture di controllo con timeout massimo 10 s. La deadline del proprietario resta quella comune dalla selezione, non viene estesa.
4. stdout: `READY receipts,text`. È **solo esito bootstrap JVM locale**, non trust/chat o prova che Apple sia pronto. TLS resta viva: il controller deve prima osservare `READY` anche sul proprietario Apple, poi inviare `CLOSE` su stdin. Chiudere prima potrebbe troncare APPROVE ancora in volo con la politica abort del proprietario.
5. Cleanup di proprietario, socket, listener, input e scheduler; output resta del controller. Un errore o timeout chiude ugualmente TLS e fallisce il processo. Il controller futuro deve ripulire anche il processo JVM e le sole identità Keychain del namespace di test. Non utilizzare credenziali Developer ID o chiavi del prodotto.

## Verifiche effettive e limite

Sei test JVM con TLS 1.3/P-256/JCA reali: doppio `READY` prima di cleanup, codice errato/input oversize/non-ASCII, controllo assente, parametri invalidi, certificato diverso dal pin selezionato e cleanup fallito senza falso marker di rifiuto. CRLF Windows corretto nel primo incremento. Suite corrente connettività: 53 riusciti, un multicast opt-in saltato. Avvio del task e rifiuto del pin invalido già verificati (exit 1 atteso). Percorsi positivo e negativo Apple/JVM compilati/eseguiti nelle run opt-in riportate sotto; nessun collaudo hardware.

## Controller e XCTest dedicati

Il launcher macOS `ios-bootstrap-interop.py` compila preventivamente jvmTest, avvia un controller TCP su `127.0.0.1`/porta effimera e un solo XCTest nello scheme **LanternBootstrapInterop**. Il simulatore deve essere già disponibile e il progetto Xcode generato come nella CI. Non usa HTTP/ATS, discovery, installer o credenziali di firma reali.

```text
python3 -B .github/scripts/ios-bootstrap-interop.py --device-id UDID_SIMULATORE
```

Lo XCTest crea un'identità OS in un namespace Keychain casuale e passa il pin pubblico al controller (`SELECT`). Solo allora parte la fixture JVM con quel pin esatto. Il controller restituisce endpoint/pin JVM; lo XCTest seleziona questo pin prima di TLS e adotta la connessione con `HandshakeV1Channel`. Alla disponibilità del codice completo invia `COMPARE`; il controller richiede uguaglianza con stdout JVM e invia `CONFIRM` soltanto al lato JVM. Lo XCTest esegue separatamente la conferma con il **ticket iOS originale**. Osservato `READY` Apple, invia `READY receipts,text`: il controller richiede anche il `READY` JVM prima di `CLOSE`/exit 0. Solo dopo chiusura TLS osservata da Apple e cleanup del namespace lo XCTest attesta `CLOSED TRANSPORT`; il launcher richiede anche `COMPLETE` e successo di xcodebuild. Nessuna di queste attestazioni autorizza chat o persiste trust.

Il canale di controllo non cifrato è esclusivamente locale, con token UUID per run, riga ASCII massima 256 byte e ordine rigido. Non trasporta chiavi/prove/contenuti. I due collegamenti di controllo e bootstrap non sono intercambiabili. Un errore del controller impedisce riuso/conferme; timeout/process exit non zero/output inatteso falliscono il collaudo. I processi macOS sono gruppi separati; `--no-daemon` impedisce al JavaExec di sfuggire alla proprietà del launcher. Cleanup su errore termina anche i processi e chiude pipe/reader; Apple ripulisce soltanto il namespace creato dal test tramite `defer`. Lo XCTest non configurato fallisce, non viene saltato.

Il target è distinto dalla suite ordinaria: la CI iOS selettiva **compila** gli XCTest opt-in, ma non avvia il collaudo JVM/iOS a ogni push. Per eseguirlo, avviare manualmente **Verify Lantern iOS → Run workflow → bootstrap_interop = true**, scegliendo `bootstrap_scenario = success` (default) oppure `mismatch`. Il parametro vale solo per workflow_dispatch; le run ordinarie non eseguono l'interoperabilità. Il launcher seleziona il solo XCTest pertinente, non salta test falliti. Risultati nativi nel relativo `.xcresult` dell'artefatto `ios-verification`. Nessun polling CI.

Usare un simulatore usa-e-getta, non quello con dati personali: una terminazione forzata di xcodebuild/runner può impedire il `defer` nel processo Apple. In quel caso il cleanup Keychain non è attestato e il simulatore isolato va rimosso da chi lo ha creato; il launcher non cancella un device ricevuto dal chiamante. La run non è superata senza attestazione di cleanup e XCTest riuscito.

## Evidenze del controller e prossimo passo

`python3 -B .github/scripts/test-ios-bootstrap-interop.py`: ora **17 test** del controller/launcher, con sostituti **solo nei test di orchestrazione** e sottoprocessi/TCP reali; ordine, pin/endpoint invalidi, confronto discordante/assente, `READY` prematuro, feature discordanti, exit fallito, output oversize/non-ASCII/extra, arresto del processo bloccato, token e limiti del server. Nuove regressioni: negativo isolato dal positivo, codici originali/alterati validati, marker/exit richiesti congiuntamente, exit non zero esplicito su sottoprocesso reale. Non sono test di crittografia o interoperabilità Apple.

Aggiornamento 5 ottobre: [CI iOS ordinaria `a619f5e`](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37231384877) riuscita: 38 XCTest ordinari/zero fallimenti, 12 test controller e nuovo target opt-in compilato (`TEST BUILD SUCCEEDED`). La successiva [run manuale con `bootstrap_interop = true`](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37274723780), stesso commit, è **conclusa `success`**: XCTest interop passato in 62,312 s, `TEST SUCCEEDED` e messaggio del launcher `Bootstrap JVM/iOS: both READY and transport/namespace cleanup observed`. Confermati pin selezionati prima di TLS, codice completo identico, prove accettate dai provider OS, doppia conferma, doppio `READY` e cleanup osservati. Riusciti anche 38 XCTest ordinari e 12 test controller. Verifica simulatore/JVM su macOS, non hardware/LAN/Android; nessun polling.

## Caso negativo di confronto (verificato in simulatore/JVM)

```text
python3 -B .github/scripts/ios-bootstrap-interop.py --device-id UDID_SIMULATORE --scenario mismatch
```

Lo XCTest `testDiscordantComparisonClosesWithoutApprovalOrReady` riusa preparazione TLS/Keychain del positivo, ma non conferma il ticket iOS. Il controller di scenario richiede `MISMATCH <codiceOriginale>:<codiceAlterato>` dopo `SELECT`: entrambi sono digest completi validi/diversi, e l'originale deve corrispondere esattamente a `COMPARISON` JVM. Solo nel test negativo invia `CONFIRM <codiceAlterato>` alla fixture: questa pubblica `REJECTED COMPARISON` e termina con errore **prima di chiamare il proprietario per firma/APPROVE**. Sono necessari sia marker sia exit 1 e reader terminato correttamente; qualsiasi `READY`, marker errato, timeout, exit 0/altro fallisce. Non si accetta un crash generico come prova del rifiuto.

Apple richiede `remoteApproved=false` su ogni snapshot, nessun `READY` e chiusura trasporto una sola volta. Verifica che il vecchio ticket/start/cancel non riaprano l'istanza, ripulisce il namespace e attesta `CLOSED TRANSPORT`. Soltanto questo percorso completo permette `COMPLETE`/successo di xcodebuild/launcher. Il marker JVM viene pubblicato soltanto dopo cleanup di proprietario/socket/listener/input/executor; eccezioni di cleanup, incluse quelle soppresse da `use`, impediscono il marker. La fixture JVM mostra un fallimento Gradle intenzionale dovuto al comando invalido; il controller non ignora fallimenti arbitrari di compilazione, TLS o protocollo. Nessuna modifica alla gestione degli errori di produzione.

JVM locale: 53 test riusciti/un multicast opt-in saltato, incluse le sei fixture con nuove asserzioni sul marker/rifiuto/chiusura I/O e regressione su cleanup fallito che impedisce il marker. XCTest non eseguibile su questo host Windows; **verificato in CI macOS/iOS simulatore** nella [run negativa 37324594616](https://github.com/zanzaro-mirco/lantern-share/actions/runs/37324594616), commit `c9d1bb4`, conclusa `success`: test passato in 71,911 s, `TEST SUCCEEDED`, launcher `Bootstrap JVM/iOS: comparison rejected without READY; transport/namespace cleanup observed`. Stessa run: 38 XCTest ordinari/zero fallimenti e 17 test controller riusciti. `ComparisonRejected` è intenzionale, accettato soltanto insieme al marker/exit previsti e alla conclusione Apple/cleanup. Nessuna prova hardware/LAN/Android o polling.

**Prossimo incremento unico:** test interop di cancellazione locale prima della conferma, chiusura osservata da entrambi e nessun `APPROVE`/`READY`, con le fixture esistenti. Non sostituire v0 né dichiarare completati i collaudi fisici della fase 1.
