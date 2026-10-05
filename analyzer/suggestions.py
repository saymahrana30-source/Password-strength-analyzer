"""Specific, actionable suggestions. They NEVER quote or display the password."""

HYGIENE = ["Use a password manager to generate and store a unique password for every account.",
           "Never reuse a password across accounts - one breach would unlock all of them (credential stuffing).",
           "Enable multi-factor authentication (MFA) wherever it is available."]


def generate_suggestions(length: int, chars: dict, findings: list, common: dict) -> list:
    kinds = {f["type"] for f in findings}
    out = []
    if common["common"]:
        out.append("Your password matches a commonly used password pattern and should not be used.")
    if length < 12:
        out.append("Use at least 12 characters; 16 or more is better. Consider a long passphrase of several unrelated words.")
    elif length < 16 and not common["common"]:
        out.append("Consider going to 16+ characters or a longer passphrase for extra safety margin.")
    seq = [f for f in findings if f["type"] == "sequence"]
    if seq:
        out.append("Your password contains a predictable " + ("numeric" if any(f["kind"] == "numeric" for f in seq) else "alphabetic")
                   + " sequence. Attackers try these first.")
    if "keyboard" in kinds:
        out.append("Avoid common keyboard sequences such as qwerty or asdf.")
    if "repetition" in kinds:
        out.append("Avoid repeated characters or repeating blocks; they add length without adding unpredictability.")
    if "common_word" in kinds or "word_plus_number" in kinds:
        out.append("Avoid dictionary words. Several random, unrelated words make a better passphrase than one word plus digits.")
    if "word_plus_number" in kinds or "common_shape" in kinds:
        out.append("Adding digits or a symbol to the end of a word is a very common habit and adds little strength.")
    if "year" in kinds:
        out.append("Avoid years and dates; they are among the first things guessed.")
    if "personal" in kinds:
        out.append("Avoid including your name, birth year, or organization - attackers try personal details early.")
    if chars["type_count"] <= 1 and length < 16:
        out.append("Mix character types, but remember that variety alone does not make a password unpredictable.")
    if not out:
        out.append("No obvious weaknesses found. Keep it unique per account and store it in a password manager.")
    return out
