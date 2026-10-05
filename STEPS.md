# Execution, GitHub, resume and interview cheat-sheet

## Run (12 steps)
1. Unzip, open a terminal in `password-strength-analyzer/`
2. `python3 -m venv venv`   3. activate it   4. `pip install -r requirements.txt`
5. `python -m unittest discover -s tests -v` (expect OK, 36 tests)
6. `python hashing_demo.py` (see salting + verification)
7. `python app.py`   8. open http://127.0.0.1:5002
9. Type in the Analyzer: watch the meter, findings and suggestions update with no page refresh
10. Click the demo buttons (123456, Password123!, aaaa…, qwerty2026!, Random 20-char); try Show/Hide password
11. Enter a demo first name / year / college under "Optional context" and type `Rahul@123`; try the Policy settings
12. Generator tab -> generate; Dashboard tab -> **Load demo statistics** -> 7 cards + 5 charts; Learn tab

## Screenshot checklist (save in `screenshots/`, demo passwords only)
Analyzer with a weak result · Analyzer with a strong generated result · personal-info warning · policy PASS vs strength
WEAK side by side · Generator · Dashboard · tests passing · `hashing_demo.py` output · folder structure.

## GitHub
`git init && git add . && git commit -m "Password strength analyzer"` -> create repo -> push. Commit in stages: detectors,
scoring, suggestions, generator, API, dashboard, tests, docs. Topics: cybersecurity, password-security, flask, appsec, nist.
Do not commit `.env` or `analytics.db`.

## Resume / LinkedIn bullet
Built a privacy-first Password Strength Analyzer (Python, Flask) with pattern-aware scoring (common-password, sequence,
keyboard, repetition, dictionary and personal-info detection), entropy estimation, a secure `secrets`-based generator,
policy checker and aggregate-only analytics; passwords never stored or logged; 36 automated tests incl. privacy tests.

## Interview Q&A
- **Why isn't `Password123!` strong?** It satisfies composition rules but is a common word plus a predictable suffix.
  Attackers use these habits first. Length, randomness and pattern resistance matter more.
- **What is entropy and where does it mislead?** `L x log2(pool)` assumes random characters. Humans aren't random, so the
  theoretical number overstates strength. This tool shows both theoretical and effective bits.
- **Why `secrets` and not `random`?** `secrets` uses the OS secure random source; `random` is predictable if its state is learned.
- **Why store no hash of the tested passwords?** It would create a database of guessable secrets for no analytic benefit.
- **Policy vs strength?** A policy is a pass/fail rule set; strength is how hard the password is to guess. `123456789012`
  can pass a length policy and still be very weak.
- **Why MFA if the password is strong?** Phishing, malware and reuse can defeat even strong passwords.
- **Online vs offline guessing?** Online is throttled by rate limiting/lockout; offline (stolen hashes) depends on the hash
  algorithm and work factor, which is why sites should use salted Argon2/bcrypt/scrypt.
- **Known limitation?** Small dictionaries and heuristics; production tools like zxcvbn do this better.
- **Why not build a cracker/time-to-crack?** Out of scope and unethical here; the project teaches defence and shows only a coarse, labelled estimate.
