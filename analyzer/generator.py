"""Password/passphrase generator using `secrets` (a cryptographically secure source).
`random` is NOT suitable: its output is predictable if the internal state is guessed. Nothing is stored."""
import math, os, secrets

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "wordlist.txt")
SETS = {"lowercase": "abcdefghijklmnopqrstuvwxyz", "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "numbers": "0123456789", "symbols": "!@#$%^&*()-_=+[]{};:,.?"}
_rng = secrets.SystemRandom()


def generate_password(length=20, uppercase=True, lowercase=True, numbers=True, symbols=True) -> str:
    chosen = [SETS[k] for k, on in (("uppercase", uppercase), ("lowercase", lowercase), ("numbers", numbers), ("symbols", symbols)) if on]
    if not chosen:
        raise ValueError("select at least one character type")
    if not 8 <= length <= 64 or length < len(chosen):
        raise ValueError("length must be between 8 and 64")
    pool = "".join(chosen)
    chars = [secrets.choice(s) for s in chosen]                    # guarantee one of each selected type
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    _rng.shuffle(chars)
    return "".join(chars)


def _words():
    with open(DATA, encoding="utf-8") as f:
        return [w.strip() for w in f if w.strip()]


def generate_passphrase(words=5, separator="-") -> dict:
    if not 3 <= words <= 10:
        raise ValueError("words must be between 3 and 10")
    wl = _words()
    phrase = separator.join(secrets.choice(wl) for _ in range(words))
    bits = round(words * math.log2(len(wl)), 1)
    return {"passphrase": phrase, "estimated_bits": bits, "wordlist_size": len(wl),
            "note": f"~{bits} bits from this {len(wl)}-word demo list. For real use pick a larger list (e.g. 7,776 words) and 5-6+ words."}
