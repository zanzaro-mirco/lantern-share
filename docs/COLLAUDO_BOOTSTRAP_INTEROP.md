# Fixture bootstrap JVM per il futuro collaudo iOS

4 ottobre 2026. Test support in `connectivity/src/jvmTest`, **non app, servizio o protocollo applicativo**. Primo lato soltanto: validato localmente con un peer JVM reale; nessun collegamento con iOS ancora eseguito.

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

Prossimo incremento unico: orchestratore macOS per questo scambio e XCTest del proprietario iOS. Dovrà dimostrare codice identico, prove accettate da entrambi i provider OS, assenza di `READY` prima delle due conferme, doppio `READY` e cleanup osservato. Non sostituire v0 e non dichiarare completati i collaudi fisici della fase 1. Nessun polling CI.
