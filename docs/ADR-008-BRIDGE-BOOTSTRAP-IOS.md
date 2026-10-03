# ADR 008 — bridge bootstrap v1 a callback per iOS

## Ambito

3 ottobre 2026. `ProtocolHandshakeBridge` comune compone `ProtocolHandshakeAttempt` e `ProtocolHandshakeFrameDecoder` per trasporti a callback; `IosHandshakeV1` in ui/iosMain espone tipi Swift senza esportare direttamente i dettagli del protocollo. Nessun chiamante nel servizio v0, nessuna socket aperta, timer, trust, database o credenziale di gruppo. Versioni e lock invariati. Non è il proprietario Network.framework né una disponibilità v1 nell'app.

La facciata richiede identità locale, nonce OS fresco, offerta canonica, pin TLS locale e remoto reali, pin selezionato esplicitamente prima di TLS, timestamp di selezione e clock monotono coerente. Verificatore sincrono vincolato al certificato realmente accettato dal trasporto. Il bridge ricontrolla il pin locale e la macchina vincola selezione/TLS/HELLO remoto; il future adapter deve prima completare TLS 1.3 reciproco tramite gli adattatori OS esistenti. Parametri di discovery non sono pin autenticati. Nessun fallback, trust-all o conferma implicita.

## Ticket e ownership

`start()` restituisce una sola richiesta HELLO; lettura e confronto sono vietati prima del callback di scrittura riuscita `sent(ticket)`. Firma dopo conferma esplicita del confronto con ticket trattenuto dalla UI. `signed(ticket, signature)` prepara APPROVE, ma solo `sent(ticket)` dal completamento del trasporto può avanzare la prova locale. Accodamento, preparazione, firma o prova remota da soli non completano il bootstrap. Identità referenziale dei ticket, non numeri riciclabili; quelli di altre istanze, duplicati o invalidati non avanzano lo stato. Array esposti copiati. I wrapper iOS non hanno costruttori pubblici.

Tutti gli ingressi, incluse letture dello stato, devono avvenire sulla queue seriale del proprietario; il bridge non è thread-safe. Firma e scrittura OS possono completare asincronamente sulla stessa queue, trattenendo il ticket originale e ricontrollando lo stato. `Ready` è un risultato locale revocabile, non completamento distribuito o autorizzazione alla chat. Una prova già in volo può arrivare al peer mentre il mittente è stato cancellato: nessun ticket permette di persistere trust da uno snapshot vecchio.

Budget di 120 secondi dalla selezione riusato dalla macchina; ricontrolli dentro i callback e prima di esporre ulteriore progresso. Il proprietario futuro deve programmare un timer con `remainingMillis()` anche senza traffico e chiudere il trasporto a `Closed`. EOF chiude anche un bootstrap `Ready`; troncamento è rilanciato. Errori frame, firma/scrittura fallite, errore clock/verificatore e cancellazione rilasciano decoder/ticket; le eccezioni non diventano successi. Firma locale invalida resta errore della macchina; errore di write/EOF distinto da input invalido e errore dell'adattatore. Nessun reset.

## Confine Swift e verifiche

Snapshot con enum fase/errore, flag prova remota e feature negoziate ordinate: niente JSON o regole crittografiche Swift duplicate. API fallibili `@Throws(Exception::class)` per conversione in errore Swift; le closure di primitive usano boxing KotlinLong/KotlinBoolean. Contratto verificato nella [documentazione ufficiale Kotlin/Native sull'interoperabilità](https://kotlinlang.org/docs/native-objc-interop.html#errors-and-exceptions), incluse le sezioni su function types e singleton. Verificatore Swift futuro restituisce esito OS, non una closure `throws` convertita automaticamente in eccezione Kotlin.

Dieci test comuni eseguiti JVM/unit Android: HELLO/callback, confronto/doppia conferma, firme/invio in attesa, ticket precedenti, framing/errori, scadenze/EOF, pin ed eccezioni. Tre XCTest scritti per importazione del framework, callback boxed, snapshot/ticket e propagazione di errori Kotlin a Swift. Questi test di confine simulano nonce/clock/verificatore e NON dimostrano TLS/crypto Apple reale; i precedenti test OS rimangono invariati. Compilazione/test Native e Swift della nuova revisione demandati alla CI macOS, non eseguiti su Windows. Comandi/conteggi in STATO.

Prossimo incremento: proprietario Network.framework isolato che componga il bridge con TLS e crypto OS, timer monotono e cleanup. Solo dopo prove native reali si potrà valutare l'instradamento nel servizio, che richiede una decisione esplicita di compatibilità. Nessuna attivazione o trust persistito in questo ADR.
