"""Pattern detectors. Every detector works on the password IN MEMORY and returns findings
that describe the weakness by TYPE and LENGTH only - never by quoting the password."""
import os, re
from analyzer.config import MIN_SEQUENCE, MIN_KEYBOARD, MIN_WORD

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]


COMMON = {pw: i + 1 for i, pw in reversed(list(enumerate(_load("common_passwords.txt"))))}   # pw -> rank
WORDS = {w for w in _load("common_words.txt") + _load("wordlist.txt") if len(w) >= MIN_WORD}

LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "l", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"})
LEET_I = str.maketrans({"1": "i"})
ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
EXTRA_WALKS = ["1qaz2wsx", "qazwsx", "qweasdzxc", "1q2w3e4r", "q1w2e3r4", "zaq12wsx", "azerty", "qwertz", "qweasd"]
YEAR_RE = re.compile(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)")
TAIL_RE = re.compile(r"[\d\W_]+$")
WORDCASE = r"(?:[a-z]{3,}|[A-Z][a-z]{2,}|[A-Z]{3,})"      # how real words are cased (not random mixed case)
SHAPE_RE = re.compile(r"^" + WORDCASE + r"[^\w\s]?\d{1,4}[^\w\s]?$")


def _walk_substrings():
    out = set()
    for row in ROWS + EXTRA_WALKS:
        for r in (row, row[::-1]):
            for i in range(len(r)):
                for j in range(i + MIN_KEYBOARD, len(r) + 1):
                    out.add(r[i:j])
    return out


WALKS = _walk_substrings()


def leet(s: str) -> str:
    return s.translate(LEET)


def merge_spans(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [tuple(x) for x in out]


# ---------------------------------------------------------------- common passwords
def is_common_password(pw: str) -> dict:
    """Exact match or a simple VARIANT (case, leetspeak, trailing digits/symbols)."""
    low = pw.lower()
    if low in COMMON:
        return {"common": True, "kind": "exact", "rank": COMMON[low]}
    cands = {leet(low), low.translate(LEET_I)}
    cands |= {TAIL_RE.sub("", c) for c in {low} | cands}
    ranks = [COMMON[c] for c in cands if c and c in COMMON]
    if ranks:
        return {"common": True, "kind": "variant", "rank": min(ranks)}
    return {"common": False, "kind": None, "rank": None}


# ---------------------------------------------------------------- sequences
def detect_sequences(pw: str, min_len: int = MIN_SEQUENCE) -> list:
    """Ascending/descending runs such as 1234, 9876, abcd, dcba."""
    s, out, i = pw.lower(), [], 0
    while i < len(s) - 1:
        j, step = i, None
        while j + 1 < len(s):
            d = ord(s[j + 1]) - ord(s[j])
            same = (s[j].isdigit() and s[j + 1].isdigit()) or (s[j].isalpha() and s[j + 1].isalpha() and s[j].isascii() and s[j + 1].isascii())
            if not same or d not in (1, -1) or (step is not None and d != step):
                break
            step, j = d, j + 1
        if j - i + 1 >= min_len:
            kind = "numeric" if s[i].isdigit() else "alphabetic"
            out.append({"type": "sequence", "kind": kind, "direction": "ascending" if step == 1 else "descending",
                        "span": (i, j + 1)})
            i = j + 1
        else:
            i += 1
    return out


# ---------------------------------------------------------------- keyboard walks
def detect_keyboard_patterns(pw: str, min_len: int = MIN_KEYBOARD) -> list:
    s, spans, i = pw.lower(), [], 0
    while i < len(s):
        best = 0
        for j in range(i + min_len, len(s) + 1):
            if s[i:j] in WALKS:
                best = j
        if best:
            spans.append((i, best))
            i = best
        else:
            i += 1
    return [{"type": "keyboard", "span": sp} for sp in merge_spans(spans)]


# ---------------------------------------------------------------- repetition
def detect_repetition(pw: str) -> list:
    s = pw.lower()
    chars = [m.span() for m in re.finditer(r"(.)\1{3,}", s)]                 # aaaa, 1111
    blocks = [m.span() for m in re.finditer(r"(.{2,6}?)\1+", s) if m.end() - m.start() >= 6]   # ababab, abcabcabc
    out = []
    for sp in merge_spans(chars + blocks):
        kind = "character" if any(a >= sp[0] and b <= sp[1] for a, b in chars) else "block"
        out.append({"type": "repetition", "kind": kind, "span": sp})
    return out


# ---------------------------------------------------------------- dictionary words / years / structure
def detect_dictionary_words(pw: str) -> list:
    """Find dictionary words (also with leetspeak). Longest-first, non-overlapping, so each real word counts once."""
    low, hits = pw.lower(), []
    for text in (low, leet(low), low.translate(LEET_I)):
        for w in WORDS:
            start = text.find(w)
            while start != -1:
                hits.append((start, start + len(w)))
                start = text.find(w, start + 1)
    chosen, used = [], set()
    for a, b in sorted(set(hits), key=lambda x: (x[0] - x[1], x[0])):      # longest first
        if not any(i in used for i in range(a, b)):
            chosen.append((a, b))
            used.update(range(a, b))
    return [{"type": "common_word", "span": sp} for sp in sorted(chosen)]


def detect_years(pw: str) -> list:
    return [{"type": "year", "span": m.span()} for m in YEAR_RE.finditer(pw)]


def detect_predictable_structure(pw: str, common: dict) -> list:
    """'word + digits/symbols' habits: welcome123, Admin2026!, Sunrise#2024, Tr0ub4dor&3.
    The finding gets a span so the entropy estimate treats those characters as cheap to guess."""
    out = []
    base = TAIL_RE.sub("", pw)
    if not base or len(base) >= len(pw) or common["common"]:
        return out
    tail = (len(base), len(pw))
    low = base.lower()
    norm = {low, leet(low), low.translate(LEET_I)}
    letters = re.sub(r"[^A-Za-z]", "", base)
    leet_word = (leet(low).isalpha() and leet(low).isascii() and low != leet(low) and len(base) >= 5
                 and tail[1] - tail[0] <= 4 and re.fullmatch(WORDCASE, letters) is not None)
    if any(n in WORDS for n in norm):
        out.append({"type": "word_plus_number", "span": tail})
    elif SHAPE_RE.match(pw) or leet_word:
        out.append({"type": "common_shape", "span": (0, len(pw))})
    return out


# ---------------------------------------------------------------- personal information
STOP = {"the", "and", "university", "college", "institute", "school", "technology", "engineering",
        "company", "limited", "ltd", "inc", "corp", "of", "for"}


def check_personal_info(pw: str, context: dict) -> list:
    """Return [{'field', 'span'}] for overlaps with the password. Only FIELD NAMES leave this function,
    never the supplied values, and the context is not stored."""
    if not context:
        return []
    low = pw.lower()
    texts = (low, leet(low), low.translate(LEET_I))
    hits = []

    def tokens(value, joined=False):
        words = [w for w in re.split(r"[^a-z]+", str(value or "").lower()) if len(w) >= 3 and w not in STOP]
        if joined and words:
            words.append("".join(words))
        return words

    def first_span(toks):
        for t in toks:
            for x in texts:
                i = x.find(t)
                if i != -1:
                    return (i, i + len(t))
        return None

    for field, toks in (("first_name", tokens(context.get("first_name"))),
                        ("organization", tokens(context.get("organization"), joined=True))):
        sp = first_span(toks)
        if sp:
            hits.append({"field": field, "span": sp})
    year = re.sub(r"\D", "", str(context.get("birth_year") or ""))
    if len(year) == 4 and year in pw:
        i = pw.find(year)
        hits.append({"field": "birth_year", "span": (i, i + 4)})
    return hits
