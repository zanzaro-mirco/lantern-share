# ADR 001 — Identità desktop nel Portachiavi macOS

Stato: implementato; provider nativo e interazione utente **da verificare su Mac Intel e Apple Silicon**.

## Decisione e confine

Su Mac l'ingresso desktop sceglie `MacKeychainIdentityStore`. Windows e Linux continuano a usare il PKCS#12 con passphrase. Il motore di rete riceve sempre `Identity`: non conosce Portachiavi, finestre di sblocco o migrazione. `KeychainAccess` limita l'adattatore a lettura e inserimento; la sostituzione in memoria compare soltanto nei test.

Si usa `KeyStore.getInstance("KeychainStore", "Apple")` del JDK 17 già richiesto, senza nuove librerie, tool esterni o password di login raccolte dall'app. La richiesta di accesso è gestita da macOS. Fonti ufficiali verificate il 27 settembre 2026: [provider OpenJDK 17](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/java.base/macosx/classes/apple/security/KeychainStore.java) e [ponte Security.framework](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/java.base/macosx/native/libosxsecurity/KeystoreImpl.m). Il provider legge il Portachiavi dell'utente e applica gli inserimenti con `store`; esporta la chiave in memoria per restituire una `PrivateKey` Java. Pertanto questa soluzione protegge la persistenza nel Portachiavi, **non rende la chiave non esportabile né usa Secure Enclave**. Va valutato un ponte nativo per firme non esportabili qualora diventi requisito.

La password casuale passata a `setKeyEntry` serve all'importazione interna del provider. Non è la password del Portachiavi e non viene salvata nel profilo. Il buffer applicativo viene azzerato dopo l'uso; JVM e provider possono mantenere copie interne non cancellabili dall'app.

## Creazione, migrazione e recupero

1. Il lock esclusivo del profilo precede ogni operazione. L'alias iniziale è `lantern-` seguito dall'hash del percorso reale; i profili separati non condividono intenzionalmente la chiave.
2. Il riferimento locale `mac-identity.ref` contiene versione, alias e fingerprint del certificato, nessun segreto. Dopo la prima apertura, spostare la cartella nello stesso account mantiene l'alias originale.
3. Se esiste `identity.p12`, si richiede la sua passphrase una volta e si importano **chiave e certificato originali**. ID, trust e database restano compatibili. Il file cifrato precedente non viene cancellato: rimane un backup protetto dalla vecchia passphrase.
4. Prima dell'importazione viene scritto atomicamente il riferimento atteso. Dopo l'importazione si riapre il provider e si verifica fingerprint e possesso della chiave con una firma. Non basta che `store` ritorni senza eccezione.
5. Riferimento corrotto, pin diverso, chiave mancante o database orfano interrompono l'avvio. Non si ripiega su un'identità nuova o su un keystore meno protetto.
6. Una migrazione interrotta può riprendere dal PKCS#12 originale soltanto se il pin coincide. Se una **nuova** creazione si interrompe prima della persistenza della chiave, rimane un riferimento senza chiave: l'app si ferma anche al riavvio. Occorre recuperare l'elemento originale o usare esplicitamente una nuova cartella di profilo. Non eliminare il riferimento per tentativi su un profilo già associato.

Il riferimento non è una difesa contro un attaccante che può modificare liberamente l'intero account/profilo. Serve a impedire rotazioni involontarie e sostituzioni incoerenti con il profilo. Copiare solo la cartella su un altro Mac non trasferisce la chiave. Backup e recupero tra dispositivi non sono una funzione di prodotto implementata.

## Evidenza e accettazione

I test portabili eseguono crittografia e filesystem reali, sostituendo esclusivamente il Portachiavi: migrazione, riapertura, spostamento, annullamento, password errata, chiave mancante/sostituita, riferimento corrotto, database orfano e importazione interrotta. Non equivalgono a prove del provider Apple.

`MacKeychainNativeTest` è escluso normalmente; con `-PmacKeychain=true` e `LANTERN_DISPOSABLE_KEYCHAIN=true` esercita importazione, lettura, firma e nuova identità sul provider reale. La CI prepara un Portachiavi usa e getta sui runner Mac delle due architetture; non modifica un Portachiavi personale. La CI non è stata eseguita da questo host Windows.

Accettazione esterna: seguire `COLLAUDO.md`, verificando anche runtime incluso, prompt, rifiuto/sblocco, riavvio del processo e riconnessione a un peer già associato. Una compilazione JVM su Windows non valida questi comportamenti.
