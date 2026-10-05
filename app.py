"""Flask backend. PRIVACY RULES: the password is processed in memory only, is never logged, never
written to the database, never put in a URL or an error message, and never sent to another service."""
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

import db
from analyzer.config import DEFAULT_POLICY, MAX_PASSWORD_LEN, CLASS_BANDS
from analyzer.engine import analyze_password
from analyzer.generator import generate_password, generate_passphrase

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024          # tiny requests only
app.config["RATE_LIMIT_PER_MIN"] = 300                 # per client IP (protects the API; see README)
db.init_db()

_hits = defaultdict(deque)
ERRORS = {400: "Bad request.", 404: "Not found.", 405: "Method not allowed.", 413: "Request too large.",
          429: "Too many requests. Please slow down.", 500: "Internal error."}


def reset_rate_limit():
    _hits.clear()


@app.before_request
def rate_limit():
    if not request.path.startswith("/api/"):
        return None
    now, q = time.time(), _hits[request.remote_addr or "?"]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= app.config["RATE_LIMIT_PER_MIN"]:
        return jsonify(error=ERRORS[429]), 429
    q.append(now)
    return None


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"      # never let a browser/proxy cache analysis results
    return resp


@app.errorhandler(Exception)
def handle_error(e):
    # Fixed messages only: never echo request data. Log just the exception TYPE, not its text.
    if isinstance(e, HTTPException):
        return jsonify(error=ERRORS.get(e.code, "Request error.")), e.code
    app.logger.error("unhandled error: %s", type(e).__name__)
    return jsonify(error=ERRORS[500]), 500


def _bad(msg, code=400):
    return jsonify(error=msg), code


def _context(raw):
    raw = raw if isinstance(raw, dict) else {}
    return {"first_name": str(raw.get("first_name") or "")[:40], "birth_year": str(raw.get("birth_year") or "")[:4],
            "organization": str(raw.get("organization") or "")[:80]}


def _policy(raw):
    raw, p = (raw if isinstance(raw, dict) else {}), dict(DEFAULT_POLICY)
    for key in ("minimum_length", "maximum_length"):
        if isinstance(raw.get(key), int) and not isinstance(raw.get(key), bool):
            p[key] = max(1, min(raw[key], 256))
    for key in ("common_password_check", "personal_info_check", "allow_spaces"):
        if isinstance(raw.get(key), bool):
            p[key] = raw[key]
    return p


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/meta")
def meta():
    return jsonify(default_policy=DEFAULT_POLICY, bands=[{"upto": u, "label": l} for u, l in CLASS_BANDS])


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    pw = data.get("password")
    if not isinstance(pw, str) or not 1 <= len(pw) <= MAX_PASSWORD_LEN:
        return _bad(f"Password must be a string of 1 to {MAX_PASSWORD_LEN} characters.")
    result = analyze_password(pw, _context(data.get("context")), _policy(data.get("policy")))
    meta_ = result.pop("_meta")                          # safe, password-free metadata
    result["recorded"] = False
    if data.get("record") is True:
        db.record(result["score"], result["classification"], meta_, "user")
        result["recorded"] = True
    return jsonify(result)


@app.post("/api/generate-password")
def gen_password():
    d = request.get_json(silent=True) or {}
    try:
        length = int(d.get("length", 20))
        pw = generate_password(length, bool(d.get("uppercase", True)), bool(d.get("lowercase", True)),
                               bool(d.get("numbers", True)), bool(d.get("symbols", True)))
    except (ValueError, TypeError):
        return _bad("Choose a length of 8-64 and at least one character type.")
    return jsonify(password=pw, length=len(pw), note="Generated with a cryptographically secure source and never stored.")


@app.post("/api/generate-passphrase")
def gen_passphrase():
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(generate_passphrase(int(d.get("words", 5))))
    except (ValueError, TypeError):
        return _bad("Choose between 3 and 10 words.")


@app.get("/api/dashboard/stats")
def dashboard_stats():
    return jsonify(db.stats())


@app.get("/api/analytics/weaknesses")
def weaknesses():
    s = db.stats()
    return jsonify(weaknesses=s["weaknesses"], patterns=s["patterns"])


DEMO = ["123456", "password", "qwerty", "letmein", "Password123!", "welcome2024", "admin@123", "qwerty2026!",
        "aaaaaaaaaaaaaaaa", "abcd1234", "Summer2026!", "iloveyou1", "1q2w3e4r", "P@ssw0rd", "Rahul@123",
        "bluefrog77", "Tr0ub4dor&3", "short7!", "AAAAAA123!", "mypasswordadmin"]


@app.post("/api/demo-seed")
def demo_seed():
    """Fill the dashboard with SYNTHETIC examples (weak demo passwords + freshly generated strong ones)."""
    pws = DEMO + [generate_password(n) for n in (12, 16, 16, 20, 20, 24, 24, 24)]
    pws += [generate_passphrase(n)["passphrase"] for n in (4, 5, 6)]
    for pw in pws:
        r = analyze_password(pw)
        db.record(r["score"], r["classification"], r["_meta"], "demo")
    return jsonify(seeded=len(pws))


@app.delete("/api/history")
def clear_history():
    db.clear()
    return jsonify(ok=True)


if __name__ == "__main__":
    # localhost only, debug OFF (debug pages can leak local variables, including passwords).
    # Use HTTPS (TLS) in any real deployment.
    app.run(host="127.0.0.1", port=5002, debug=False)
