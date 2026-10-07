# Dichiarazione di ammissione al gruppo

Incremento di dominio preparatorio al protocollo v1: `GroupAdmissionClaim` contiene gruppo, emittente e destinatario. È una **dichiarazione non firmata**, non una credenziale verificata o un'appartenenza autorizzata. Non sostituisce l'ammissione PoC wire 0 né `ProtocolHandshakeApproval`, che prova solo il transcript della connessione corrente.

Gli ID nel dominio sono opachi e non vuoti; non vengono normalizzati. Emittente e destinatario devono essere diversi. L'auto-ammissione è rifiutata: la fondazione del gruppo richiederà un percorso distinto. Non sono introdotti ruoli amministrativi, scadenze o revoche globali assenti dalla specifica.

`bindingTo(groupId, issuerId, memberId)` confronta esattamente tutti i campi con un contesto stabilito indipendentemente dalla dichiarazione. Distingue gruppo, emittente o destinatario discordante; `MATCHED` significa soltanto corrispondenza strutturale. **Non significa firma valida, emittente autorizzato, conferma utente o protezione dai replay.** Passare come contesto gli stessi campi appena ricevuti non verifica nulla.

L'appartenenza futura sarà legata al gruppo, non a SSID, IP o sessione LAN, così da persistere al cambio rete. Prima di accettare e persistere una credenziale serviranno almeno:

- formato canonico versionato con dominio di firma distinto, validazione degli ID crittografici e limiti del payload;
- firma verificata con l'identità dell'emittente e prova della sua appartenenza al medesimo gruppo;
- collegamento al processo di ammissione e alle conferme esplicite previste, senza promozione da mDNS o dal solo `READY`;
- gestione dell'emittente iniziale, delle ammissioni delegate e del completamento recuperabile, prima di integrare trust e database.

Nessuno di questi passaggi viene simulato in produzione o dichiarato implementato da questo incremento. Il confronto non include un contatore d'ammissione alla sessione: esclusione della cronologia anteriore e destinatari dei messaggi restano regole separate da implementare.

Verifica: nove casi comuni per corrispondenza, sostituzioni dei tre campi, inversione dei ruoli, auto-ammissione, campi/contesto vuoti e confronto senza normalizzazione. Eseguiti con `./gradlew -Pandroid=true :domain:jvmTest :domain:testDebugUnitTest --console=plain`; includendo le otto regressioni sessione, 17 test per target. Test unitari Android su JVM, non hardware; Native richiede checkpoint manuale. Nessuna migrazione SQLite, modifica wire, versione o lock.
