# 🔐 Password Strength Analyzer & Security Suggestion Tool

A beginner-friendly, **defensive and educational** cybersecurity project. Type a password and get an instant,
explainable assessment: score (0-100), class, length/character analysis, common-password, sequence, keyboard,
repetition, dictionary and personal-information checks, an entropy-style estimate, specific suggestions,
a policy check, a secure password/passphrase generator and a privacy-safe analytics dashboard.

## Privacy and ethics (the design rules)
- The password is processed **in memory only**: never stored, never logged, never put in a URL, never in an error
  message, never sent to a third party.
- The database keeps **aggregate metadata only** (score, class, length, pattern counts, weakness categories).
  It deliberately stores **no hash** either: hashes of arbitrary user passwords would create a new target for offline guessing.
- Optional personal context (name, birth year, organization) is compared locally and **never stored**.
- **No password cracking, no credential testing, no external lookups.** The "guess resistance" table is a coarse,
  labelled *educational estimate*, not a "time to crack" promise.
- Use **synthetic demo passwords** for screenshots and testing. Never reuse demo passwords.

## Key idea
```
LENGTH + UNPREDICTABILITY + PATTERN RESISTANCE + COMMON-PASSWORD CHECKS + CONTEXT  =  better password assessment
```
Composition rules alone fail: `Password123!` has upper, lower, digit and symbol, and is still one of the first guesses.
The tool shows this directly: its *theoretical* entropy is high, its *effective* (pattern-aware) entropy is tiny.

## Architecture
```
Browser (meter, show/hide, generator, dashboard)  ->  POST /api/analyze  ->  analyzer.engine
   engine = length | characters | common check | sequences | keyboard | repetition | dictionary/year/structure | personal
          -> entropy (theoretical + effective) -> score + class -> suggestions + policy + guess-resistance
   (optional, off by default) metadata only -> SQLite -> dashboard
```

## Folder guide
| Path | Purpose |
|---|---|
| `app.py` | Flask API, rate limiting, safe error handling, security headers (port 5002) |
| `db.py` | SQLite, metadata only |
| `analyzer/config.py` | **All bands, weights, penalties, caps** (edit here) |
| `analyzer/patterns.py` | Detectors: common, sequence, keyboard, repetition, words, years, structure, personal |
| `analyzer/scoring.py` | Length/character analysis, entropy, 0-100 score, guess-resistance estimate |
| `analyzer/suggestions.py` | Specific suggestions (never quote the password) |
| `analyzer/generator.py` | Password/passphrase generator using `secrets` |
| `analyzer/policy.py` | POLICY PASS/FAIL (separate from strength) |
| `analyzer/hashing_demo.py` + `hashing_demo.py` | Separate demo: salted scrypt hash + verify (synthetic password only) |
| `data/` | Small educational lists (common passwords, common words, passphrase words) |
| `templates/index.html` | Analyzer, Generator, Dashboard, Learn tabs |
| `tests/` | 36 tests incl. privacy tests |

## Run it
```bash
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python hashing_demo.py              # optional: safe password storage demo
python app.py                       # open http://127.0.0.1:5002
```

## How the score works (project-defined, not a universal standard)
| Component | Max | Idea |
|---|---|---|
| Length | 35 | `length x 35/16`, so 16+ characters earns the full 35 |
| Character diversity | 15 | counts types present, helps but is not decisive |
| Unique-character ratio | 10 | punishes `aaaa…` |
| Pattern resistance | 20 | share of the password NOT covered by recognised patterns (dictionary words count at half weight) |
| Not a common password | 10 | exact match or simple variant (case, leetspeak, trailing digits) |
| Unpredictability | 10 | pattern-aware effective entropy, 60 bits = full marks |

**Penalties** for common password, keyboard walk, sequence, repetition, personal info, dictionary word, year, and
"word + digits" habits. **Caps** keep weak passwords weak: a common password cannot exceed 15, anything under
30 effective bits cannot exceed 30, under 45 bits cannot exceed 50, under 60 bits cannot exceed 60, and passwords
under 8 characters are capped at 35 (under 6 at 15).
Classes: 0-20 VERY WEAK · 21-40 WEAK · 41-60 MODERATE · 61-80 STRONG · 81-100 VERY STRONG.

**Entropy:** `theoretical = L x log2(pool)` assumes random characters. Humans are not random, so the *effective* estimate
treats characters inside recognised patterns as cheap. Neither number is a guarantee.

## Demo results (synthetic passwords)
| Input | Score | Class | Why |
|---|---|---|---|
| `123456` | 0 | VERY WEAK | common, short, numeric sequence |
| `Password123!` | 30 | WEAK | all 4 character types, but common word + predictable digits |
| `aaaaaaaaaaaaaaaa` | 30 | WEAK | long but one repeated character |
| `qwerty2026!` | 25 | WEAK | keyboard walk + year |
| random 20-char (generated) | ~99 | VERY STRONG | long, random, no patterns |

Random generated passwords were also checked: 0 of 9,000 (12/16/20 characters) scored below 70.

## API
`POST /api/analyze` (body: `password`, optional `context`, `policy`, `record`) · `POST /api/generate-password` ·
`POST /api/generate-passphrase` · `GET /api/dashboard/stats` · `GET /api/analytics/weaknesses` · `POST /api/demo-seed` ·
`DELETE /api/history`
- **Validation:** password must be a string of 1-256 characters; context/policy are sanitised and length-limited.
- **Status codes:** 200 OK, 400 invalid input, 404 unknown route, 413 body too large, 429 rate limited, 500 generic error.
- **Errors** use fixed messages and never echo input; only the exception *type* is logged.
- **Rate limiting:** 300 requests/minute per IP (in-memory; use a shared store in production).
- **HTTPS is required in production** so the password is encrypted in transit. Debug mode is off (debug pages can expose variables).

## Limitations (say this in interviews)
- Heuristic, not a proof. Real tools such as **zxcvbn** use huge ranked dictionaries and smarter matching.
- The common-password and word lists are tiny and English-only. A human-made password built from words not on the
  list (for example a leetspeak spelling of an uncommon word) can be over-rated.
- The passphrase generator uses a 304-word demo list (~8 bits/word); real use needs a larger list (e.g. 7,776 words).
- No breach-database lookup (that would mean sending data out; see future work).
- The live meter sends each (debounced) keystroke to the local server. A production design could run the analyzer in the browser.
- Guess-resistance buckets rest on assumed guess rates and are illustrative only.

## Future work
Breach check via k-anonymity (send only a 5-character hash prefix), client-side analyzer, larger dictionaries / zxcvbn
integration, localisation, Docker, accessibility audit, optional Argon2 in the hashing demo.
