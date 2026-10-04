# Collaudo bootstrap JVM ↔ iOS (opt-in)

4 ottobre 2026. Test support in `connectivity/src/jvmTest`, `.github/scripts` e `iosApp/InteropTests`, **non app, servizio o protocollo applicativo**. Lato JVM validato localmente con un peer JVM reale; controller verificato su Windows. Collegamento Apple scritto, ma non ancora compilato/eseguito su questo host.

## Avvio e precondizioni

Il controller deve ottenere il pin pubblico dell'identità Apple di test e selezionarlo **prima di TLS**. Nessun pin da discovery, trust-all, chiave condivisa o conferma implicita. Il task usa JDK 17 e classpath jvmTest; non esporta `HandshakeV1Connection` né aggiunge dipendenze/versioni.

```text
./gradlew :connectivity:runHandshakeV1InteropFixture -PinteropPeerPin=PIN_APPLE_64_HEX --quiet --console=plain
```

Su Windows usare `gradlew.bat`. Sostituire il segnaposto con il pin minuscolo di 64 caratteri effettivamente selezionato. Il controller deve tenere stdin aperto, leggere stdout senza bloccare il processo e limitarne la durata complessiva; non avviare questa fixture come servizio persistente. stderr/exit non zero indicano fallimento, mai successo parziale. Il formato sotto è controllo del test, **non wire v1**, e non viene utilizzato dall'app.

## Controllo del test

1. stdout: `LISTENING 127.0.0.1 <port> <jvmPin>`. Identità JCA nuova in memoria; nessuna PKCS#12 o identità dell'utente. Il controller passa il pin JVM come selezione esplicita al trasporto Apple prima della connessione. Listener limitato a IPv4 loopback, TLS 1.3 reciproca, pin peer esatto, attesa accept/TLS limitata a 10 s.
2. Si scambiano HELLO attraverso i proprietari e i codec esistenti. stdout: `COMPARISON <sha256Completo>`. Il controller deve confrontarlo con il codice esposto dal proprietario Apple. Solo se coincidono, simulare le due conferme UI con il rispettivo ticket corrente. Nessuna decisione del protocollo viene spostata nel controller.
3. stdin: `CONFIRM <sha256Completo>` seguito da LF o CRLF. Il server firma e scrive APPROVE reale, attende/verifica la prova remota e richiede `READY` locale. Comando assente, troncato, non ASCII, troppo lungo o discordante termina senza concedere progresso; letture di controllo con timeout massimo 10 s. La deadline del proprietario resta quella comune dalla selezione, non viene estesa.
4. stdout: `READY receipts,text`. È **solo esito bootstrap JVM locale**, non trust/chat o prova che Apple sia pronto. TLS resta viva: il controller deve prima osservare `READY` anche sul proprietario Apple, poi inviare `CLOSE` su stdin. Chiudere prima potrebbe troncare APPROVE ancora in volo con la politica abort del proprietario.
5. Cleanup di proprietario, socket, listener, input e scheduler; output resta del controller. Un errore o timeout chiude ugualmente TLS e fallisce il processo. Il controller futuro deve ripulire anche il processo JVM e le sole identità Keychain del namespace di test. Non utilizzare credenziali Developer ID o chiavi del prodotto.

## Verifiche effettive e limite

Cinque test JVM con TLS 1.3/P-256/JCA reali: doppio `READY` prima di cleanup, codice errato/input oversize/non-ASCII, controllo assente, parametri invalidi e certificato diverso dal pin selezionato. CRLF Windows corretto dopo il primo test mirato fallito. Suite finale connettività: 52 riusciti, un multicast opt-in saltato. Avvio del task e rifiuto del pin invalido verificati (exit 1 atteso). CLI positiva con processo Apple, accessibilità del loopback dal simulatore e orchestrazione di pin/conferme **non ancora verificate**.

## Controller e XCTest dedicati

Il launcher macOS `ios-bootstrap-interop.py` compila preventivamente jvmTest, avvia un controller TCP su `127.0.0.1`/porta effimera e un solo XCTest nello scheme **LanternBootstrapInterop**. Il simulatore deve essere già disponibile e il progetto Xcode generato come nella CI. Non usa HTTP/ATS, discovery, installer o credenziali di firma reali.

```text
python3 -B .github/scripts/ios-bootstrap-interop.py --device-id UDID_SIMULATORE
```

Lo XCTest crea un'identità OS in un namespace Keychain casuale e passa il pin pubblico al controller (`SELECT`). Solo allora parte la fixture JVM con quel pin esatto. Il controller restituisce endpoint/pin JVM; lo XCTest seleziona questo pin prima di TLS e adotta la connessione con `HandshakeV1Channel`. Alla disponibilità del codice completo invia `COMPARE`; il controller richiede uguaglianza con stdout JVM e invia `CONFIRM` soltanto al lato JVM. Lo XCTest esegue separatamente la conferma con il **ticket iOS originale**. Osservato `READY` Apple, invia `READY receipts,text`: il controller richiede anche il `READY` JVM prima di `CLOSE`/exit 0. Solo dopo chiusura TLS osservata da Apple e cleanup del namespace lo XCTest attesta `CLOSED TRANSPORT`; il launcher richiede anche `COMPLETE` e successo di xcodebuild. Nessuna di queste attestazioni autorizza chat o persiste trust.

Il canale di controllo non cifrato è esclusivamente locale, con token UUID per run, riga ASCII massima 256 byte e ordine rigido. Non trasporta chiavi/prove/contenuti. I due collegamenti di controllo e bootstrap non sono intercambiabili. Un errore del controller impedisce riuso/conferme; timeout/process exit non zero/output inatteso falliscono il collaudo. I processi macOS sono gruppi separati; `--no-daemon` impedisce al JavaExec di sfuggire alla proprietà del launcher. Cleanup su errore termina anche i processi e chiude pipe/reader; Apple ripulisce soltanto il namespace creato dal test tramite `defer`. Lo XCTest non configurato fallisce, non viene saltato.

Il target è distinto dalla suite ordinaria: la CI iOS selettiva **compila** anche questo XCTest, ma non avvia il collaudo JVM/iOS a ogni push. Per eseguirlo, avviare manualmente **Verify Lantern iOS → Run workflow → bootstrap_interop = true**. Il parametro vale solo per workflow_dispatch; le run ordinarie non eseguono l'interoperabilità. Risultati nativi nel relativo `.xcresult` dell'artefatto `ios-verification`. Nessun polling CI.

Usare un simulatore usa-e-getta, non quello con dati personali: una terminazione forzata di xcodebuild/runner può impedire il `defer` nel processo Apple. In quel caso il cleanup Keychain non è attestato e il simulatore isolato va rimosso da chi lo ha creato; il launcher non cancella un device ricevuto dal chiamante. La run non è superata senza attestazione di cleanup e XCTest riuscito.

## Evidenze del controller e prossimo passo

`python3 -B .github/scripts/test-ios-bootstrap-interop.py`: 12 test del controller/launcher, con sostituti **solo nei test di orchestrazione** e sottoprocessi/TCP reali; ordine, pin/endpoint invalidi, confronto discordante/assente, `READY` prematuro, feature discordanti, exit fallito, output oversize/non-ASCII/extra, arresto del processo bloccato, token e limiti del server. Non sono test di crittografia o interoperabilità Apple.

**Prossimo incremento unico:** eseguire una run manuale con `bootstrap_interop = true`, verificare compilazione ed effettivo successo del collegamento JVM ↔ iOS e correggere solo eventuali errori di quel percorso. La raggiungibilità del loopback del simulatore, espansione della variabile dello scheme e compatibilità reciproca dei provider OS rimangono da verificare con quella run. Non sostituire v0 e non dichiarare completati i collaudi fisici della fase 1.
