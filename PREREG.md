# PREREG — terzo verificatore delle condizioni dell'acceptance record (x402 tsc#4)

Scritto il 2026-10-11 (UTC 20:49 circa) PRIMA di scrivere il verificatore e prima di eseguirlo sui vettori.
Il suo sha256 è registrato nel messaggio del commit che lo introduce.

## Fonti lette (e solo queste)

| File locale | Origine | sha256 |
|---|---|---|
| `fonti/5a4ea06_README.md` | babyblueviper1/preaction-governance-conformance @ 5a4ea06, `examples/acceptance-record-cold/README.md` | 9c1b7a74…c419 |
| `fonti/5a4ea06_vectors.json` | idem, `vectors.json` | c7f5513a…e7e0 |
| `fonti/646588c_README.md` | idem @ 646588c | f7731aa1…bd4a |
| `fonti/646588c_vectors.json` | idem @ 646588c | c7f5513a…e7e0 (identico byte per byte a 5a4ea06) |
| `fonti/draft-krausz-verification-state-03.txt` | ietf.org/archive/id | 1d142b3e…bed9 |
| `fonti/tsc4_comments.json` | `gh api repos/x402-foundation/tsc/issues/4/comments --paginate` (145 commenti) | nel commit |

Non letti, non scaricati, non aperti: `build_vectors.py`, `run_vectors.py`, `tools/` e ogni altro codice di
preaction-governance-conformance; il repo actaseal/x402-acceptance-check-cold e ogni codice di actaseal; codice di
altri verificatori. I file sono stati scaricati uno per uno con `gh api .../contents/<path>?ref=<commit>`, senza clonare.

Dichiarazione di non-indipendenza: ho letto il README a 5a4ea06, che contiene già i tre chiarimenti nati dal
confronto con actaseal. Su quei tre punti questo verificatore NON è indipendente.

## Cosa si confronta

Per ogni vettore, l'oggetto `expect`. Un campo è **pinned** se e solo se la sua chiave è presente in `expect` di
quel vettore. Campi possibili osservati: `result`, `conditions`, `disposition`, `key_step`, `policy_refusal`.

- `conditions`: confronto come INSIEME (README: «Condition lists compare as sets»); un duplicato nel mio output
  conta come disaccordo (non deve esistere).
- gli altri: uguaglianza esatta di valore JSON (tipo compreso: `true` ≠ `1`, `null` ≠ assente).
- un campo non pinned non entra nel conteggio; il mio valore viene comunque riportato in tabella come informativo.
- un vettore «concorda» se concordano TUTTI i suoi campi pinned. Esito: N/25 vettori e conteggio per campo.

Il verificatore riceve solo `case`; `expect`, `what` e `id` non gli vengono passati (il runner li separa prima).

## Controllo positivo (deve far fallire il banco prima che il banco dica «concorda»)

1. Verificatore «accetta sempre» (`result: verified`, `conditions: []`, `disposition: accepted`) sullo stesso
   runner: attesi molti disaccordi (ogni vettore il cui result pinned non è `verified`, più i tre `verified` con
   disposition ≠ accepted). Se dà 25/25 il runner è rotto.
2. Vettori alterati: (a) un byte della firma di `acc-accepted-verified` cambiato → il mio verificatore deve
   dare `malformed`/`signature_invalid` e quindi disaccordo con l'attesa `verified`; (b) `expect.result` di un
   vettore cambiato a mano → disaccordo; (c) `conditions` attese con una condizione in più → disaccordo.
3. Mutanti del mio verificatore (ognuno deve far cadere almeno un vettore o un test generativo): precede non
   stretto, niente soppressione per tipo, autorità valutata anche su malformed, signature_invalid come token
   proprio, hash ben tipato = qualunque stringa, firma non verificata, key_unresolved senza fermarsi.
4. Ed25519: test vector RFC 8032 §7.1 (TEST 1, 2, 3, SHA(abc)) e, se presente, confronto con `cryptography`
   (opzionale, solo per il controllo) su firme generate e alterate.

## Letture da fissare (dal testo; se il testo non decide, «testo ambiguo» con le due letture)

Le scrivo in `RAPPORTO.md` con la frase del README / -03 su cui poggiano. Le estensioni che il testo non
nomina (nomi di condizione fuori vocabolario, errori di input) sono dichiarate come MIE e non pinned da alcun vettore.

## Lettura «prima del chiarimento» (646588c)

Misuro anche, sugli stessi 25 vettori, le varianti che il testo a 646588c ammetteva sui tre punti:
(1) `signature_invalid` come token di result proprio con `conditions: []`; (2) «ill-typed» = non stringa JSON;
(3) disposition riportata anche su malformed. Riporto quanti vettori cambiano con ciascuna. Non posso
dichiarare quale avrei scelto senza aver letto il chiarimento: lo dico.

## Test generativi

Mutazioni di casi costruiti da me (chiavi mie, firme RFC 8032 mie), con classe attesa scritta a mano dal testo
in una tabella separata dal codice: chiavi ignote a ogni livello, tipi sbagliati, duplicati JSON, firme alterate,
base64url non canonico, hash non canonici (maiuscole, 63/65 caratteri, `\n` finale), timestamp non canonici.
