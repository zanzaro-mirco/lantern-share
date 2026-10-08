# Dichiarazione di ammissione al gruppo

Incremento di dominio preparatorio al protocollo v1: `GroupAdmissionClaim` contiene gruppo, emittente e destinatario. È una **dichiarazione non firmata**, non una credenziale verificata o un'appartenenza autorizzata. Non sostituisce l'ammissione PoC wire 0 né `ProtocolHandshakeApproval`, che prova solo il transcript della connessione corrente.

Gli ID nel dominio sono opachi e non vuoti; non vengono normalizzati. Emittente e destinatario devono essere diversi. L'auto-ammissione è rifiutata: la fondazione del gruppo richiederà un percorso distinto. Non sono introdotti ruoli amministrativi, scadenze o revoche globali assenti dalla specifica.

`bindingTo(groupId, issuerId, memberId)` confronta esattamente tutti i campi con un contesto stabilito indipendentemente dalla dichiarazione. Distingue gruppo, emittente o destinatario discordante; `MATCHED` significa soltanto corrispondenza strutturale. **Non significa firma valida, emittente autorizzato, conferma utente o protezione dai replay.** Passare come contesto gli stessi campi appena ricevuti non verifica nulla.

L'appartenenza futura sarà legata al gruppo, non a SSID, IP o sessione LAN, così da persistere al cambio rete. Prima di accettare e persistere una credenziale serviranno almeno:

- formato canonico versionato con dominio di firma distinto, validazione degli ID crittografici e limiti del payload;
- firma verificata con l'identità dell'emittente e prova della sua appartenenza al medesimo gruppo;
- collegamento al processo di ammissione e alle conferme esplicite previste, senza promozione da mDNS o dal solo `READY`;
- gestione dell'emittente iniziale, delle ammissioni delegate e del completamento recuperabile, prima di integrare trust e database.

Il formato, il controllo di firma, la verifica isolata di una catena ancorata e il contenitore della prova completa descritti sotto sono implementati. Restano da implementare la fondazione/adozione confermata della radice, lo scambio nel servizio attivo, il processo di ammissione recuperabile e l'integrazione trust/database. Il confronto non include un contatore d'ammissione alla sessione: esclusione della cronologia anteriore e destinatari dei messaggi restano regole separate da implementare.

Verifica: nove casi comuni per corrispondenza, sostituzioni dei tre campi, inversione dei ruoli, auto-ammissione, campi/contesto vuoti e confronto senza normalizzazione. Eseguiti con `./gradlew -Pandroid=true :domain:jvmTest :domain:testDebugUnitTest --console=plain`; includendo le otto regressioni sessione, 17 test per target. Test unitari Android su JVM, non hardware; Native richiede checkpoint manuale. Nessuna migrazione SQLite, modifica wire, versione o lock.

## Formato isolato v1

`GroupAdmissionCodec` codifica quattro campi obbligatori, nell'ordine canonico `version`, `group`, `issuer`, `member`. Versione esattamente il numero JSON `1`: stringhe, spellings numerici alternativi e versioni sconosciute sono rifiutati. Nessun fallback al wire 0.

Tutti e tre gli ID sono esattamente 64 caratteri esadecimali minuscoli. Il gruppo rappresenta un valore casuale da 256 bit, indipendente da rete e dispositivo; le identità mantengono il pin SHA-256 del DER del certificato. Si riusa la validazione sintattica esistente, non la semantica del certificato per il gruppo. Generazione casuale e verifica certificati non sono eseguite dal codec. Il modello di dominio rimane opaco; è il confine protocollo a imporre queste rappresentazioni.

Payload unsigned: massimo 512 byte UTF-8, profondità JSON massima 1. Payload `SignedGroupAdmissionCodec`: massimo 1024 byte, profondità 2, due campi obbligatori `claim` e `signature`:

```json
{"claim":{"version":1,"group":"<64 hex>","issuer":"<64 hex>","member":"<64 hex>"},"signature":"<Base64 canonico>"}
```

L'esempio usa segnaposto, non è un payload valido. La versione appartiene alla dichiarazione annidata: un secondo campo `version` esterno è sconosciuto e rifiutato. Il serializer annidato è lo stesso di quello unsigned, non una seconda implementazione della validazione. Il limite del documento annidato è quello dell'envelope completo; il limite standalone di 512 byte non è un secondo limite sul whitespace interno all'envelope.

Ordine/whitespace/escape JSON validi non cambiano la dichiarazione né i byte da firmare. Duplicati, anche con nomi escaped equivalenti, campi mancanti/sconosciuti, tipi errati e auto-ammissione sono rifiutati. Dimensione, UTF-8 rigoroso e profondità sono controllati prima della deserializzazione. Il test di profondità è deliberatamente **entro il limite di byte**, per non confonderlo con il rifiuto oversize; UTF-8 invalido richiede `CharacterCodingException`, secondo la [API Kotlin](https://kotlinlang.org/api/core/kotlin-stdlib/kotlin.text/decode-to-string.html), non un generico errore di runtime.

La firma usa Base64 standard canonico, 4–256 caratteri, con padding/bit inutilizzati corretti. La regola sintattica è condivisa con APPROVE, la cui API/semantica rimane invariata. La sintassi accetta anche byte che non sono una firma DER/ECDSA valida: `SignedGroupAdmission` è un contenitore **non verificato**, non un'autorizzazione.

## Byte canonici e vettore

`GroupAdmissionCodec.signedBytes` concatena campi con prefisso `lunghezzaDecimaleUTF8:valore`, senza separatori aggiuntivi, in quest'ordine:

1. `lantern-group-admission-1`;
2. `1`;
3. gruppo;
4. emittente;
5. destinatario.

Il dominio distinto impedisce confusione con transcript, APPROVE o firma wire 0. I ruoli non vengono ordinati: invertirli cambia i byte. Si firmano questi byte ricostruiti, **non il JSON ricevuto**. Le firme ECDSA SHA-256 DER rimangono compito delle API OS, non di un algoritmo Kotlin nuovo.

Vettore pubblico indipendente (.NET SHA-256 e JCA): gruppo `c` × 64, emittente `a` × 64, destinatario `b` × 64. JSON canonico unsigned: 240 byte. Byte da firmare: 232 byte, prefisso `25:lantern-group-admission-11:1`, seguito dai tre campi `64:<ID>`. SHA-256: `3e3fcddb32360c5166a63cdfc093b17ab6043a7acf51755bae7e7ce40cb43029`.

Le prove P-256 JVM reali verificano round-trip dell'envelope e rifiuto con chiave, gruppo, emittente, destinatario, direzione, versione o dominio cambiati. Non provano che gli ID fixture corrispondano a certificati reali, né interoperabilità Apple del nuovo formato.

## Controllo di firma, non appartenenza

`GroupAdmissionSignatureVerification.verify` riceve contesto atteso, fingerprint del certificato del firmatario e callback OS legata **alla chiave di quello stesso certificato**. Il contesto e il pin devono essere stabiliti indipendentemente dal payload; copiare i campi ricevuti nei parametri non è una verifica d'identità o di gruppo.

Prima di chiamare il verificatore controlla gruppo/emittente/destinatario e pin dell'emittente; poi passa i byte canonici e la firma. Firma invalida → `InvalidSignature`; errori inattesi dell'adattatore propagati, mai trasformati in successo. L'adattatore deve restituire false per DER/firme invalide riconosciute dal verificatore OS. I test comuni usano un sostituto solo per provare ordine/binding/errori; quelli JVM usano firme P-256 reali.

`VerifiedSignature` significa esclusivamente corrispondenza e firma verificata sul certificato dichiarato dal contratto dell'adattatore. **Non prova che l'emittente sia membro autorizzato**, non fonda il gruppo, non attesta conferme, non rende recuperabile il commit, non autorizza messaggi e non scrive trust. Una credenziale persistente può legittimamente essere ripresentata al cambio rete; la firma da sola non è protezione anti-replay del processo interattivo.

Prima dell'attivazione servirà una radice di gruppo verificabile e una catena di ammissioni delegate senza autorizzazioni circolari, oltre a conferme esplicite, completamento recuperabile e rispetto dei blocchi locali. Nessun certificato sconosciuto va accettato automaticamente in base al solo envelope o a `VerifiedSignature`.

Il verificatore è sincrono e senza stato: non possiede socket, timer o tentativi e non rende immutabile l'autorizzazione del contesto. Il futuro proprietario deve mantenere il legame tra risultato, dichiarazione e tentativo corrente, e ricontrollare appartenenza/blocco/uscita dal gruppo prima del commit. Un risultato conservato non deve ripristinare una selezione cancellata o autorizzare un'altra dichiarazione. La gestione di questa concorrenza non è implementata dal codec.

## Verifica attuale

Nuovi test: 11 codec unsigned, 7 envelope, 5 verificatore comune, 3 JVM con SHA-256/P-256 reali. Suite protocollo con regressioni esistenti: **126 JVM, 119 unit Android**, zero errori/fallimenti/skipped. Native e integrazione Apple del nuovo codice non ancora eseguiti; test comuni inclusi nel checkpoint iOS manuale già esistente. Formato completamente isolato dal servizio PoC, schema SQLite e identità invariati.

## Radice e ammissioni delegate — incremento successivo

`GroupTrustAnchor(groupId, founderId)` identifica l'origine del gruppo stabilita **indipendentemente dalla prova ricevuta**. Il costruttore valida soltanto ID opachi non vuoti: non fonda il gruppo, non verifica un certificato e non autorizza l'adozione della radice annunciata da un peer. Al confine protocollo gruppo/fondatore/destinatario atteso devono essere 64 hex minuscoli. La futura fondazione locale richiederà generazione OS casuale e identità persistente; l'adozione da parte di un nuovo membro richiederà binding alle conferme del bootstrap. Entrambi i percorsi restano non implementati.

`GroupAdmissionChainVerification.verify` riceve questa radice, il destinatario atteso e **un percorso ordinato** di `SignedGroupAdmission`: fondatore → membro → eventuali altri membri → destinatario. Non cerca un percorso in un grafo ostile. Ogni dichiarazione deve appartenere allo stesso gruppo, avere come emittente il destinatario precedente e introdurre un'identità non ancora visitata. Una lista vuota non prova la fondazione; auto-ammissioni, ritorni al fondatore, cicli, frammenti scollegati, riordino e destinatario finale diverso sono rifiutati. Si controlla tutta la struttura prima di invocare la crittografia; non si espongono appartenenze parziali.

La funzione conserva una copia della lista limitata prima dei callback (le dichiarazioni sono immutabili). L'input deve essere uno snapshot posseduto dal chiamante, non una collezione modificata concorrentemente durante la copia. Ogni firma è verificata sui byte canonici già definiti. Il callback OS riceve il fingerprint **atteso** dell'emittente: deve risolvere/verificare il certificato con quel fingerprint e usare la chiave dello stesso certificato. Chiave sconosciuta, pin discordante o firma invalida → false; errori inattesi e cancellazione propagati. Questo adattatore certificati non è ancora integrato: i test comuni sostituiscono solo il callback e quelli JVM usano chiavi P-256 effimere con ID fixture dichiarati, non certificati/Keychain.

`VerifiedChain` prova esclusivamente le firme e il percorso fino alla radice fornita. Non è un token di autorizzazione, non conferma il tentativo corrente, non risolve replay/commit o blocchi locali e non scrive nel trust. Non basta passare la radice ricevuta per rendere affidabile una catena. Prima del commit il futuro proprietario dovrà ricontrollare radice corrente, dichiarazione/destinatario, conferme, blocco/uscita e cancellazione del tentativo. Nessuna promozione da `READY`.

Limite isolato: **32 dichiarazioni per percorso**, controllato prima della copia o delle firme per limitare memoria/lavoro crittografico. Non limita a 32 i membri del gruppo e non cambia il wire esistente; un percorso più lungo viene rifiutato esplicitamente, mai troncato. Il formato della prova completa è definito sotto; la gestione di percorsi troppo lunghi resta da definire prima dell'attivazione. Il fondatore è una radice storica, non un amministratore o un server: non deve essere online per verificare una prova e ogni membro verificato può delegare. Nessuna revoca globale aggiunta.

Verifica locale del nuovo incremento: tre test dominio, nove comuni di catena e due JVM P-256 reali (round-trip codec, chiave sbagliata/mancante per ciascun emittente, cambio gruppo/destinatario). Suite complessive **20 dominio per target, 137 protocollo JVM/128 unit Android**, zero errori/fallimenti/skipped. Android unit su JVM; nessun collaudo fisico o esecuzione Native della nuova catena. API completamente isolate da rete/UI/SQLite, nessuna migrazione o nuova dipendenza.

## Prova completa v1 — 8 ottobre 2026

`GroupAdmissionProofCodec` definisce l'envelope isolato, con campi obbligatori nell'ordine canonico `version`, `anchor`, `admissions`:

```json
{"version":1,"anchor":{"group":"<64 hex>","founder":"<64 hex>"},"admissions":[{"claim":{"version":1,"group":"<64 hex>","issuer":"<64 hex>","member":"<64 hex>"},"signature":"<Base64 canonico>"}]}
```

Segnaposto illustrativi, non un payload valido. La versione esterna deve essere esattamente il numero JSON `1`; ogni dichiarazione conserva la propria versione firmata, senza fallback al wire 0. La radice contiene soltanto gruppo e fondatore, entrambi 64 hex minuscoli. Nessun ruolo amministrativo, certificato o chiave privata nel contenitore; il resolver dei certificati resta responsabilità dell'adattatore OS non ancora integrato.

Limiti: **32768 byte UTF-8 totali**, profondità massima **4** (envelope → array → ammissione → dichiarazione), **1–32 ammissioni**. L'elemento 33 è rifiutato prima di deserializzarne il contenuto. Il limite totale governa anche il whitespace delle dichiarazioni annidate: i limiti standalone 512/1024 byte dei codec singoli non sono ulteriori limiti per elemento. ID e firme mantengono tutti i vincoli esistenti tramite gli stessi serializer. Campi sconosciuti, mancanti, duplicati anche escaped, tipi/versioni sbagliati, UTF-8 invalido e profondità eccessiva sono rifiutati. Nessun troncamento o salto di elementi malformati.

`GroupAdmissionProof` è un contenitore **non verificato**: copia il percorso all'ingresso e restituisce copie nelle letture; il chiamante non deve modificare concorrentemente l'input durante la copia. Il codec non controlla topologia/firme, non conserva trust e non adotta la radice. Si usa l'overload `GroupAdmissionChainVerification.verify(proof, expectedAnchor, expectedMemberId, callback)` con radice/destinatario stabiliti indipendentemente: `AnchorMismatch` rifiuta entrambe le possibili sostituzioni della radice prima della crittografia; poi valgono tutti i controlli di catena precedenti. Passare `proof.anchor` come radice attesa annulla questo confine di sicurezza.

Nessuna firma aggiuntiva sull'envelope: le ammissioni firmano già versione/gruppo/emittente/destinatario; la radice deve coincidere con quella locale e ordine/continuità/destinatario sono verificati. Il contenitore non è una dichiarazione di fondazione. Una prova vuota non può autorizzare il fondatore. Prima della fondazione/adozione di una nuova radice servirà il collegamento esplicito alle conferme del bootstrap; non si può inferirlo dalla ricezione di un JSON valido o dal solo `VerifiedChain`.

Nuove verifiche: 11 test comuni del formato/prova e una integrazione JVM P-256 del round-trip completo, firma di entrambi gli emittenti e radice alternativa. Il caso da 32 elementi controlla il limite sintattico, non dichiara verificata una catena con identità ripetute. Nessuna integrazione nel wire attivo, SQLite o UI; nessun test fisico/Native del nuovo formato.

## Binding crittografico delle conferme — 8 ottobre 2026

Le firme `ProtocolHandshakeApproval` esistenti coprono il transcript bootstrap, **non la prova di gruppo**. Il loro `READY` non consente quindi l'adozione della radice né l'ammissione. Non si modifica APPROVE per assegnargli implicitamente un significato diverso.

`GroupAdmissionConfirmationContext` congela i byte di un contesto separato. Riceve le offerte bootstrap compatibili, con identità TLS verificate e nonce OS freschi, la radice attesa indipendente e la prova. Richiede radice corrispondente e ruoli uguali all'ultima ammissione: emittente attuale → nuovo membro. Il costruttore **non verifica la catena o le firme**; un contesto costruito non è una credenziale. La verifica dell'intera catena resta obbligatoria prima di proseguire, senza adottare automaticamente la radice proposta dal peer.

Byte di confronto canonici: prefissi `lunghezzaDecimaleUTF8:valore`, concatenati in ordine:

1. `lantern-group-admission-confirm-1`;
2. identità dell'emittente;
3. identità del nuovo membro;
4. transcript bootstrap completo, prodotto da `ProtocolHandshakeTranscript.bytes`;
5. JSON canonico della prova completa, prodotto da `GroupAdmissionProofCodec.encode`.

Le viste `comparisonBytes()` sono copie difensive. Il futuro adattatore calcolerà SHA-256 OS per mostrare il codice completo su entrambi i dispositivi. Ordine/whitespace/escape del JSON ricevuto non lo cambiano; firma, radice, ordine del percorso, nonce o capability diversi invece lo cambiano. Due firme ECDSA diverse sulla stessa dichiarazione producono intenzionalmente due contesti diversi: entrambi devono confrontare **la stessa prova completa**, non soltanto una dichiarazione equivalente.

`approvalBytes(senderIdentity)` aggiunge un dominio e una direzione distinti, ancora con lunghezze UTF-8: `lantern-group-admission-confirm-approve-1`, mittente, destinatario, byte di confronto completi. Sono i byte per la futura firma OS dopo conferma esplicita di questo confronto. Non sono il JSON o la firma della credenziale persistente e non possono sostituire APPROVE bootstrap o wire 0. Nessun nuovo frame di rete viene attivato in questo incremento.

`GroupAdmissionConfirmationVerification.verifyRemote` controlla ruoli/destinatario e fingerprint del peer TLS prima del callback OS sullo stesso certificato; controlla Base64 canonico e verifica la firma direzionale. Firma invalida → rifiuto; errori inattesi/cancellazione propagati. `VerifiedRemoteConfirmation` significa **una sola attestazione crittografica remota**, non due conferme, catena valida, tentativo corrente o trust persistente. Non dimostra che l'utente remoto abbia premuto un pulsante: l'emissione della firma deve essere governata dal proprietario remoto e dalla sua conferma esplicita.

Limite dei componenti stateless: non possiedono ticket, connessione, timer o transazione e non invalidano da soli un risultato vecchio. Il ciclo di vita condiviso descritto sotto ora governa ticket/conferme/esito write e invalidazione, ma gli adattatori di rete/timer/UI devono ancora esservi collegati. Fondazione/adozione della radice, resolver certificati e commit recuperabile restano non implementati. Nessuna integrazione nel servizio/UI/database.

Verifica locale: sette nuovi casi comuni di binding/ordine/errori e due JVM P-256 reali. **158 protocollo JVM/146 unit Android**, zero errori/fallimenti/skipped; metadata comuni e compilazione Android/desktop riusciti. Coperti entrambe le direzioni, chiave errata, firme bootstrap/ammissione non riutilizzabili, nonce/gruppo/fondatore/firma della prova sostituiti, capability, normalizzazione JSON, buffer, ruoli/ancora incompatibili e cancellazione propagata dal verificatore. Non sono test di cancellazione di un proprietario, TLS/certificati reali, Native o hardware. Nessuna versione/lock/migrazione modificata.

## Tentativo di conferma gruppo — ciclo di vita condiviso

`GroupAdmissionConfirmationAttempt` possiede un solo contesto immutabile e i suoi ticket. Non gestisce socket, repository o primitive OS. Il proprietario della connessione deve serializzare **tutte** le chiamate sulla stessa coda, fornire identità/offerte TLS e pin scelti per quel canale, usare nonces freschi a ogni riconnessione e inoltrare tempestivamente blocco, uscita, cancellazione ed EOF. Non si può riutilizzare o resettare un tentativo chiuso.

`prepare()` verifica l'intera prova tramite il callback OS, che deve risolvere ciascun certificato rispetto al pin atteso, e soltanto dopo restituisce il ticket di confronto. Prova malformata/firma invalida non espongono il confronto; radice/ruoli restano quelli congelati nel contesto indipendente. Il componente non adotta una nuova radice. Prima della fondazione/adozione confermata resta necessario il percorso di prodotto separato.

La UI mantiene l'oggetto `GroupAdmissionComparison` esatto; `confirm(ticket)` dopo il confronto esplicito del codice completo produce un ticket `Sign` con copia dei byte da firmare. Il callback OS `signed(request, signature)` deve firmare esattamente quei byte con la chiave dell'identità TLS locale; produce dati `Send` separati da APPROVE bootstrap, non ancora un frame di rete. Solo `sent(send)` nel callback di **scrittura realmente completata**, non dopo l'accodamento, attesta la progressione locale. Ticket di altri tentativi, riutilizzati o revocati non avanzano lo stato; le viste di byte sono copie.

La conferma remota può arrivare prima/durante/dopo firma e scrittura locali, ma solo dopo la prova verificata. Deve avere direzione corretta e firma OS del peer TLS sullo stesso contesto. `Confirmed` richiede **catena verificata, conferma esplicita locale, scrittura locale riuscita e firma remota verificata**. Duplicati, riflessioni, ingresso prima della prova o rientranza del verificatore remoto chiudono il tentativo. Nessuna appartenenza parziale è esposta.

Scadenza: 120000 ms dalla selezione originale, sullo stesso orologio monotono del bootstrap; `prepare()` non riavvia il budget. `state` e `remainingMillis` applicano la scadenza anche a `Confirmed`; arretramento/overflow o guasto dell'orologio non lasciano uno stato attivo. Il proprietario deve comunque programmare un timer usando il budget residuo per chiudere il trasporto anche quando nessuno chiama il core.

`cancel()`, `block()`, `leaveGroup()` e `transportClosed()` chiudono anche `Confirmed`, conservano il primo motivo e invalidano ticket. Il core ricontrolla stato/deadline dopo i callback di verifica; un callback che cancella/blocca il tentativo o termina dopo la scadenza non ripristina il progresso. Errori inattesi/cancellazione chiudono e vengono rilanciati. La conferma non costituisce una transazione: il futuro proprietario dovrà verificare ancora tentativo/radice/blocco/uscita correnti prima del commit e implementare il completamento distribuito recuperabile. Nessun messaggio o trust persistente viene autorizzato qui.

Verificato locale: 13 nuovi test comuni di ciclo di vita e un JVM con due tentativi/P-256 reale, chiavi effimere e ID fixture (non TLS o certificati reali). Suite protocollo **172 JVM/159 unit Android**, zero fallimenti/errori/skipped. Prova obbligatoria/rotta, entrambe le sequenze e quattro tempi della conferma remota, ticket stranieri, write/sign falliti, pin sostituiti, chiusure anche dopo conferma, cancellazione/blocco/timeout nei callback, rientranza, guasto/arretramento/overflow dell'orologio. Metadata comuni e Android/desktop compilati; unit Android su JVM, non hardware/Native. Wire 0/SQLite/versioni/lock invariati. Adattatori timer/UI/rete e resolver certificati ancora non integrati.
