# ADR 023 — uscita durevole locale dal gruppo

Data: 3 novembre 2026. Blocco approvato dall'utente, implementato in questo incremento; pubblicazione autorizzata dall’utente.

## Comportamento

Il pannello esistente offre «Esci dal gruppo» a fondatore e membro adottato,
con conferma esplicita legata all'esatta appartenenza visualizzata. Il servizio
LAN viene arrestato e resta arrestato; un successivo avvio è esplicito.
L'uscita non modifica gli altri dispositivi e non è una revoca globale.

L'owner ferma selezioni, socket e memoria della sessione, poi attende anche i
lavori delle selezioni già ritirate. Su JVM il nodo impedisce nuovi avvii durante
il drain e la transazione; su iOS il servizio usa `admissionDrains.notify` sulla
coda seriale, senza bloccare i callback che devono completare il drain.
Un commit già iniziato può finire prima dell'uscita, senza ACK dopo lo stop.

## Persistenza e autorizzazioni

Una transazione elimina fondazione oppure adozione committata per radice e
identità attese, insieme all'eventuale journal della stessa appartenenza.
Un journal estraneo o uno stato conflittuale causano rollback. La prima DELETE
acquisisce il lock di scrittura prima delle letture. Nessuna modifica allo
schema SQLite 5, alle migrazioni o al wire.

Identità OS, nome, trust PoC separato, testi, ricevute e contatori sono conservati.
La storia non ripristina appartenenza o sessione: dopo l'uscita un membro deve
essere ammesso di nuovo con un confronto vivo; il fondatore può anche creare
esplicitamente un gruppo. Le vecchie credenziali non sono revocate sugli altri
dispositivi. Il limite dei destinatari congelati di ADR 022 resta aperto.

Il successo è pubblicato dopo rilettura dell'assenza di appartenenza/journal.
Un errore resta visibile come stato incerto, senza replay o refresh automatico:
si recupera con «Rileggi stato salvato». Una chiusura non viene riattivata dalle
risposte in ritardo.

## Verifica e confini

Regressioni SQLite per conservazione dati, identità/radice errate e rollback del
journal; servizio UI per click stantii ed errore dopo commit; Node/TLS/SQLite
reali per uscita di fondatore/membro, rientro esplicito, preparazione e commit
concorrenti. I due XCTest del controller nativo sono riusciti nel completo Apple
41804002151 su `bc6ba39` (4 novembre 2026, 206 test, zero fallimenti): uscita
della fondazione su SQLite Native/riapertura ed errore con rilettura esplicita,
senza riattivare un controller chiuso. Evidenze e comandi in STATO.
Simulatore automatico, UI interattiva e hardware restano livelli distinti.

Esclusi revoca globale, notifiche agli altri membri, recupero, reconnect,
pulizia della storia, distribuzione automatica e UI completa.
