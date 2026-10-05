"""Length/character analysis, entropy-style estimate and the 0-100 score."""
import math
from analyzer.config import (CLASS_BANDS, LENGTH_BANDS, MAX_POINTS, PENALTIES, ENTROPY_CAPS, COMMON_EXACT_CAP,
                             COMMON_VARIANT_CAP, PATTERN_BITS, POOL_SIZES, GUESS_SCENARIOS, LENGTH_CAPS)
from analyzer.patterns import merge_spans


def analyze_length(pw: str) -> dict:
    n = len(pw)
    band = next(label for limit, label in LENGTH_BANDS if n < limit)
    return {"length": n, "band": band,
            "note": "Length helps a lot, but length alone is not security: 'aaaaaaaaaaaaaaaa' is long and still predictable."}


def analyze_characters(pw: str) -> dict:
    present = []
    if any(c.islower() and c.isascii() for c in pw): present.append("lowercase")
    if any(c.isupper() and c.isascii() for c in pw): present.append("uppercase")
    if any(c.isdigit() and c.isascii() for c in pw): present.append("numbers")
    if any(c.isascii() and not c.isalnum() and c != " " for c in pw): present.append("symbols")
    if " " in pw: present.append("spaces")
    if any(not c.isascii() for c in pw): present.append("unicode")
    unique = len(set(pw))
    return {"types": present, "type_count": len(present), "unique_count": unique,
            "unique_ratio": round(unique / len(pw), 2) if pw else 0,
            "note": "Variety can help, but 'Password123!' has all four types and is still highly predictable."}


def estimate_theoretical_entropy(pw: str, types: list) -> float:
    """Entropy ~ L x log2(N). ASSUMES every character was chosen at random - humans don't, so this is
    optimistic for human-made passwords. It is combined with pattern analysis, never used alone."""
    pool = sum(POOL_SIZES[t] for t in types) or 1
    return round(len(pw) * math.log2(max(pool, 2)), 1)


def estimate_effective_entropy(pw: str, types: list, findings: list, common: dict) -> float:
    """Pattern-aware estimate: characters inside recognised patterns count as cheap, not random."""
    pool = max(sum(POOL_SIZES[t] for t in types), 2)
    spans = merge_spans([f["span"] for f in findings if f.get("span")])
    covered_idx = {i for a, b in spans for i in range(a, b)}
    bits = 0.0
    for i, ch in enumerate(pw):
        if i in covered_idx:
            continue
        between = (i - 1) in covered_idx and (i + 1) in covered_idx and not ch.isalnum()
        bits += 3 if between else math.log2(pool)       # a lone separator between known pieces is cheap (e.g. '-')
    spanned = [f for f in findings if f.get("span")]
    def nested(f):    # a pattern inside a bigger pattern adds no extra bits (it is already accounted for)
        a, b = f["span"]
        return any(g is not f and g["span"][0] <= a and b <= g["span"][1] and g["span"] != f["span"] for g in spanned)
    bits += sum(PATTERN_BITS.get(f["type"], 0) for f in spanned if not nested(f))
    if common["common"]:
        bits = min(bits, math.log2(common["rank"] + 1) + 2 + (8 if common["kind"] == "variant" else 0))
    return round(bits, 1)


def coverage_fraction(pw: str, findings: list) -> float:
    """Share of the password covered by recognised patterns. Dictionary words count at half weight
    so a long passphrase of unrelated words is not treated like 'password123'."""
    if not pw:
        return 0
    other = merge_spans([f["span"] for f in findings if f.get("span") and f["type"] != "common_word"])
    every = merge_spans([f["span"] for f in findings if f.get("span")])
    cov_other = sum(b - a for a, b in other)
    cov_extra = sum(b - a for a, b in every) - cov_other
    return min(1.0, (cov_other + 0.5 * cov_extra) / len(pw))


def classify(score: int) -> str:
    return next(label for limit, label in CLASS_BANDS if score <= limit)


def calculate_score(pw: str, chars: dict, findings: list, common: dict, effective_bits: float) -> tuple:
    """Return (score, component_points, penalty_points). Bands are project-defined, not a standard."""
    P = MAX_POINTS
    comp = {
        "length": min(P["length"], round(len(pw) * P["length"] / 16)),
        "diversity": round(P["diversity"] * min(1, chars["type_count"] / 4)),
        "unique_ratio": round(P["unique_ratio"] * chars["unique_ratio"]),
        "pattern_resistance": round(P["pattern_resistance"] * (1 - coverage_fraction(pw, findings))),
        "non_common": 0 if common["common"] else P["non_common"],
        "unpredictability": round(P["unpredictability"] * min(1, effective_bits / 60)),
    }
    kinds = [f["type"] for f in findings]
    if common["common"]:
        kinds.append("common_exact" if common["kind"] == "exact" else "common_variant")
        kinds = [k for k in kinds if k != "word_plus_number"]
    pen = {}
    for k in set(kinds):
        per, cap = PENALTIES[k]
        pen[k] = min(cap, per * kinds.count(k))
    score = sum(comp.values()) - sum(pen.values())
    if common["common"]:
        score = min(score, COMMON_EXACT_CAP if common["kind"] == "exact" else COMMON_VARIANT_CAP)
    for len_below, cap in LENGTH_CAPS:
        if len(pw) < len_below:
            score = min(score, cap)
            break
    for bits_below, cap in ENTROPY_CAPS:
        if effective_bits < bits_below:
            score = min(score, cap)
            break
    return max(0, min(100, int(score))), comp, pen


def _bucket(seconds: float) -> str:
    if seconds < 60: return "under a minute"
    if seconds < 3600: return "minutes"
    if seconds < 86400: return "hours"
    if seconds < 86400 * 365: return "days to months"
    if seconds < 86400 * 365 * 1000: return "years to centuries"
    return "far beyond practical limits"


def guess_resistance(effective_bits: float) -> dict:
    """Coarse, labelled estimate. NOT a promise and NOT an exact 'time to crack'."""
    avg_guesses = 2 ** max(effective_bits - 1, 0)
    return {"label": "Educational estimate only",
            "caveat": "Real guessing resistance depends on the attacker model, how predictable the password is, "
                      "the hashing algorithm and work factor, rate limiting, and online vs offline access.",
            "scenarios": [{"name": n, "assumption": a, "estimate": _bucket(avg_guesses / rate)} for n, rate, a in GUESS_SCENARIOS]}
