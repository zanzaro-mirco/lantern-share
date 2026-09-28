# ADR 003 — Trasporto TLS iOS con Network.framework

Data: 28 settembre 2026. Stato: implementato, verifica nativa CI pendente.

## Contesto

Lantern usa identità P-256 persistenti e TLS 1.3 con autenticazione reciproca. Su iOS l'identità è già conservata nel Keychain come `SecIdentity`, mentre formato wire, limiti e validazione dei frame appartengono al modulo Kotlin `protocol`. L'annuncio Bonjour non costituisce autorizzazione.

## Decisione

`AppleTLSTransport` è l'adattatore Network.framework e crea `NWListener` e `NWConnection` configurati esclusivamente per TLS 1.3. Presenta la `SecIdentity` locale, richiede il certificato del peer e completa la verifica solo se il certificato:

- corrisponde esattamente a uno dei pin esplicitamente ammessi dal chiamante;
- usa una chiave EC P-256 e una firma ECDSA con SHA-256;
- è temporalmente valido, autofirmato e possiede una firma verificabile.

Il listener riceve una funzione che restituisce lo snapshot corrente dei pin autorizzati o selezionati. Un insieme vuoto o un pin malformato rifiuta l'handshake. Il trasporto non legge annunci Bonjour per decidere il trust e non persiste autorizzazioni.

Network.framework trasporta soltanto byte. `WireFrameDecoder` nel modulo Kotlin `protocol` implementa il prefisso uint32 big endian, il limite di 65.536 byte, l'accumulo incrementale e la validazione tramite `Wire`. `IosWireFraming` espone questo confine al codice Swift senza duplicare JSON o regole del protocollo.

Il chiamante possiede listener e connessioni restituiti e deve cancellarli al termine. Associazione, HELLO, confronto del codice, conferme, persistenza del trust e messaggistica restano fuori da questo incremento.

## Conseguenze e verifica

Il pinning non usa CA pubbliche, hostname, TOFU o trust-all. Il certificato autofirmato è accettato soltanto dopo i controlli sopra descritti. Una futura modifica del certificato o del formato wire richiederà una decisione e una migrazione esplicite.

I test Kotlin verificano frame frammentati e consecutivi, lunghezze non valide, reset dopo errore e rifiuto dei payload che non rispettano `Wire`. Gli XCTest avviano un listener e una connessione loopback reali, verificano TLS 1.3 reciproco con trasferimento di byte e il fallimento con pin errato. Tali XCTest richiedono Xcode/simulatore e non sono eseguibili sull'host Windows.
