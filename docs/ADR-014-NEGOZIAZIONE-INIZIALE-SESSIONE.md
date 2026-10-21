# ADR 014 — negoziazione iniziale di sessione sul TLS vivo

Data: 21 ottobre 2026. Blocco B5, prima integrazione Android/desktop.

## Risultato e confini

L'azione esplicita **Negozia sessione** su entrambi i Node confronta lo stato della
sessione LAN corrente dopo una nuova verifica delle appartenenze sullo stesso TLS.
Il pannello mostra la decisione locale. Non legge la cronologia, non scrive SQLite,
non concede trust PoC e non attiva chat, recupero, riconnessione o traffico di gruppo.
Il trasporto termina dopo lo scambio: la decisione non è un handle di autorizzazione
riusabile né una conferma del risultato remoto.

Si tratta del primo percorso esplicito fra due partecipanti, non della gestione
completa delle sessioni: iOS, snapshot multipartecipante aggiornati, cambio rete
automatico, scelta operativa fra sessioni usate e ciclo di vita del futuro canale
applicativo restano aperti. Nessuna restrizione aggiunta ai requisiti del prodotto.

## Regole condivise

`GroupSessionOffer` distingue una sessione mantenuta dal servizio da una proposta
casuale nuova, non ancora stabilita. Entrambe sono osservazioni non attendibili
prima dei controlli di trasporto/appartenenza.

- Una proposta nuova non può essere già utilizzata.
- Se almeno uno mantiene una sessione, le proposte nuove sono soltanto fallback:
  un dispositivo che rientra raggiunge la sessione rimasta, anche quando vuota.
- Se nessuno mantiene una sessione, le due proposte casuali vuote convergono.
- Il core riusa `SessionSelector`: minimo deterministico fra vuote, precedenza
  dell'unica usata, scelta esplicita fra più usate, conflitti rifiutati.
- Nessun reset di `used` da pulizia della cronologia. Questo blocco non produce
  contenuti e crea soltanto sessioni vuote; il futuro writer dovrà rendere `used`
  monotono prima di pubblicare contenuti, senza aggirare la scelta richiesta.

Il Node conserva una sola sessione in memoria, associata a radice e marker completo
esatto dell'appartenenza. Una nuova negoziazione fallita non la sostituisce. La
chiusura del pannello annulla la selezione, non il gruppo o la sessione mantenuta.
`Node.stop` elimina sempre la sessione; una nuova attivazione non la ricava dal
database, da SSID/IP, dagli annunci o dalla cronologia. Se l'altro resta attivo,
quello che rientra può raggiungerne la sessione. Se entrambi si arrestano, una nuova
negoziazione genera nuovi ID. Il cambio LAN richiede ancora stop/riavvio esplicito.

## Compatibilità e formato

Entrambi gli HELLO devono supportare E richiedere **group-membership-check** e
**group-session-selection**. I vecchi peer e il solo percorso B4 rifiutano la
continuazione per incompatibilità; nessuno sniffing o fallback. B4 e i formati
precedenti rimangono identici. Nessuna migrazione schema, versione dipendenze,
lock o modifica dei workflow.

Dopo il consueto scambio membership LGM, ogni destinatario verifica la prova con
radice locale indipendente e pin TLS effettivo PRIMA di leggere/scrivere offerte
di sessione. Il risultato B4 precedente non viene consultato. Segue un solo frame
uint32 big endian, lunghezza ESATTAMENTE 133 validata prima del payload:

| Offset | Contenuto |
|---|---|
| 0–3 | ASCII `LSN` e byte versione 1 |
| 4–67 | gruppo, 64 byte ASCII hex minuscoli |
| 68–131 | ID sessione, 64 byte ASCII hex minuscoli, casuale a 256 bit |
| 132 | 0 proposta nuova vuota; 2 sessione mantenuta vuota; 3 mantenuta usata |

Altri flag, lunghezze, byte, gruppi diversi, troncamenti e dati ulteriori sono
rifiutati. Il codec è Kotlin comune; non esiste un codec OS distinto.

## Ownership e arbitraggio

`HandshakeV1Connection.negotiateSession` conserva owner, socket, endpoint TLS e
deadline originale di 120 secondi; lo scambio LGM e quello LSN non riarmano timer.
Il pin minore scrive per primo in entrambe le fasi, l'altro legge e poi scrive.
Le letture sono esatte, ogni lettura e le write verificano il lifetime; la verifica
OS avviene senza state lock. Cancel e scadenza interrompono anche I/O bloccato.
I vecchi confronti/APPROVE, altre negoziazioni e il trasferimento all'ammissione
non possono riutilizzare l'owner dopo l'inizio dello scambio.

Il servizio ricontrolla radice, marker esatto, selezione e deadline prima e dopo
la verifica OS e prima di accettare il risultato. La pubblicazione e la sessione
locale sono arbitrate con cancel/stop sotto un lock breve, senza socket, SQLite
o OS sotto quel lock. Callback vecchi non installano sessioni in una nuova run.
L'ultimo writer attende solo EOF entro la stessa deadline per non troncare byte
TLS accodati; EOF non prova l'esito remoto. Lo stop non cancella l'appartenenza.

## Accettazione e prossimo utilizzatore

Test comuni per formato/negoziazione/scelta; test OS mantenuti per framing esatto,
EOF/flush/deadline, owner non riusabile e cancel/scadenza in receive dopo prova
P-256 vera; test Node/TLS/SQLite riaperto in entrambi gli ordinamenti, membri
delegati col fondatore offline, continuità/nuovo ID, gruppi errati e modalità
incompatibili senza trust/commit/storia. Evidenze effettive in STATO, non hardware.

Prossimo blocco: consumare lo stesso formato/regole nel servizio Bonjour iOS, con
stesso owner e lifetime, sessione in memoria limitata alla run, interfaccia
diagnostica e checkpoint Native/simulatore. Non dichiarare B5 multipiattaforma o
sessioni complete prima di integrazione/verifica; hardware fase 1 sempre aperto.
