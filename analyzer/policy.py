"""Password policy checker. POLICY PASS/FAIL is a different question from STRENGTH SCORE."""
from analyzer.config import DEFAULT_POLICY


def check_policy(pw: str, policy: dict, common: dict, personal: list, has_context: bool) -> dict:
    p = {**DEFAULT_POLICY, **(policy or {})}
    checks = [
        {"name": "Minimum length", "passed": len(pw) >= p["minimum_length"],
         "message": f"At least {p['minimum_length']} characters required."},
        {"name": "Maximum length", "passed": len(pw) <= p["maximum_length"],
         "message": f"Up to {p['maximum_length']} characters must be supported."},
        {"name": "Spaces", "passed": p["allow_spaces"] or " " not in pw,
         "message": "Spaces are allowed." if p["allow_spaces"] else "Spaces are not allowed."},
    ]
    if p["common_password_check"]:
        checks.append({"name": "Common-password check", "passed": not common["common"], "message": "Common passwords are rejected."})
    if p["personal_info_check"]:
        checks.append({"name": "Personal-information check", "passed": not personal,
                       "message": "Passwords containing the supplied personal details are rejected." if has_context
                                  else "No personal details supplied, so nothing to compare."})
    ok = all(c["passed"] for c in checks)
    return {"result": "POLICY PASS" if ok else "POLICY FAIL", "checks": checks,
            "note": "Policy compliance is not the same as strength: a password can pass a policy and still be predictable."}
