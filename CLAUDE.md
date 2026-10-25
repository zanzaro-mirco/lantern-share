# Ripartenza Lantern con Claude Code

Comunica in italiano e lavora sul repository esistente. Prima di modificare leggi e applica **[AGENTS.md](AGENTS.md)**: è la fonte comune delle istruzioni operative anche per Claude Code. Quindi leggi [PASSAGGIO_CONSEGNE.md](PASSAGGIO_CONSEGNE.md), [PIANO_SVILUPPO.md](PIANO_SVILUPPO.md), [ARCHITETTURA_E_QUALITA.md](ARCHITETTURA_E_QUALITA.md) e la sintesi corrente di [STATO_SVILUPPO.md](STATO_SVILUPPO.md). Non caricare tutto lo storico.

Guida dettagliata esterna di questa consegna: `../LANTERN_RIPARTENZA_CLAUDE_CODE.md`, creata il 25 ottobre 2026 nella cartella superiore del progetto. Se assente su un altro clone, i documenti nel repository bastano alla ripartenza. [Indice dei documenti e loro ambito](docs/STATO_DOCUMENTAZIONE.md). La guida è una fotografia: verificare sempre Git, piano e stato correnti prima di agire.

Niente subagenti salvo richiesta esplicita; un solo blocco funzionale alla volta, integrazione completa e test pertinenti, senza refactoring estranei o nuove versioni. Preservare modifiche locali, identità, schema e wire. Un push raggruppato quando autorizzato; nessun polling/attesa/automazione CI, niente build per sole modifiche Markdown. Non confondere compilazione, test automatici, simulatore e hardware.

Fotografia della consegna: codice `3d22698`, B8 testo/roster e copie integrati anche iOS; PoC success, completo Apple 40209149857 pendente nell'ultima lettura. Prima recuperare l'esito da concluso/correggere; poi unico blocco copie originali dopo nuovi ingressi con destinatari congelati. Fase 0 chiusa; fase 1/hardware e gate UI aperti. Non ricominciare identità, SQLite, TLS o associazione già realizzati.
