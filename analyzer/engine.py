"""Orchestrates all analyzers. The password lives only in local variables for the duration of the call."""
from analyzer.config import DEFAULT_POLICY
from analyzer import patterns as pt
from analyzer.scoring import (analyze_length, analyze_characters, estimate_theoretical_entropy, estimate_effective_entropy,
                              calculate_score, classify, guess_resistance)
from analyzer.suggestions import generate_suggestions, HYGIENE
from analyzer.policy import check_policy

DISCLAIMER = ("Password strength cannot be perfectly determined by one formula. The score and bands are project-defined, "
              "pattern-aware estimates for learning.")


def analyze_password(pw: str, context: dict = None, policy: dict = None) -> dict:
    common = pt.is_common_password(pw)
    length = analyze_length(pw)
    chars = analyze_characters(pw)

    raw = (pt.detect_sequences(pw) + pt.detect_keyboard_patterns(pw) + pt.detect_repetition(pw)
           + pt.detect_dictionary_words(pw) + pt.detect_years(pw) + pt.detect_predictable_structure(pw, common))
    pm = pt.check_personal_info(pw, context or {})
    matched = [m["field"] for m in pm]
    raw += [{"type": "personal", "field": m["field"], "span": m["span"]} for m in pm]

    theo = estimate_theoretical_entropy(pw, chars["types"])
    eff = estimate_effective_entropy(pw, chars["types"], raw, common)
    score, comp, pen = calculate_score(pw, chars, raw, common, eff)

    findings = _describe(raw, common, length, chars, eff)
    suggestions = generate_suggestions(len(pw), chars, raw, common)
    pattern_types = sorted({f["type"] for f in raw if f["type"] not in ("personal",)})
    weakness_types = []
    if common["common"]: weakness_types.append("common_password")
    if len(pw) < 12: weakness_types.append("too_short")
    if chars["type_count"] <= 1: weakness_types.append("low_diversity")
    if matched: weakness_types.append("personal_info")
    if eff < 35: weakness_types.append("low_entropy")

    return {
        "score": score, "classification": classify(score),
        "length_analysis": length, "character_analysis": chars,
        "entropy": {"theoretical_bits": theo, "effective_bits": eff,
                    "note": "Theoretical = length x log2(pool), assuming random characters (optimistic for human-made passwords). "
                            "Effective discounts recognised patterns."},
        "findings": findings, "suggestions": suggestions, "hygiene": HYGIENE,
        "score_breakdown": {"components": comp, "penalties": pen},
        "guess_resistance": guess_resistance(eff),
        "policy": check_policy(pw, policy, common, matched, bool(context and any(context.values()))),
        "disclaimer": DISCLAIMER,
        # metadata used for optional aggregate analytics (contains NO password data)
        "_meta": {"length": len(pw), "pattern_count": len(raw), "patterns": pattern_types, "weaknesses": weakness_types},
    }


def _describe(raw, common, length, chars, eff) -> list:
    out = []
    good = length["length"] >= 12
    out.append({"severity": "good" if good else "warn",
                "message": f"{'Good' if good else 'Low'} length ({length['length']} characters - {length['band'].lower()})."})
    out.append({"severity": "good" if chars["type_count"] >= 3 else "warn",
                "message": f"Character variety: {chars['type_count']} type(s) ({', '.join(chars['types']) or 'none'}). Variety alone does not guarantee strength."})
    if common["common"]:
        out.append({"severity": "bad", "message": "Matches a commonly used password pattern and should not be used."
                    + (" (exact match)" if common["kind"] == "exact" else " (close variant)")})
    else:
        out.append({"severity": "good", "message": "Not found in the local common-password list."})
    msgs = {"sequence": lambda f: f"Predictable {f['direction']} {f['kind']} sequence ({f['span'][1] - f['span'][0]} characters).",
            "keyboard": lambda f: f"Keyboard pattern detected ({f['span'][1] - f['span'][0]} characters).",
            "repetition": lambda f: f"Repeated {f['kind']} pattern ({f['span'][1] - f['span'][0]} characters).",
            "common_word": lambda f: f"Common dictionary word ({f['span'][1] - f['span'][0]} characters).",
            "year": lambda f: "A year-like number (19xx/20xx) is present.",
            "word_plus_number": lambda f: "Common word followed by digits/symbols - a very predictable structure.",
            "common_shape": lambda f: "Shape 'Capitalised word + digits (+ symbol)' is extremely common.",
            "personal": lambda f: "Password appears to contain personal information (" + f["field"].replace("_", " ") + ")."}
    for f in raw:
        out.append({"severity": "warn", "type": f["type"], "message": msgs[f["type"]](f)})
    if not raw and not common["common"]:
        out.append({"severity": "good", "message": "No sequence, keyboard, repetition, dictionary or personal patterns detected."})
    return out
