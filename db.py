"""SQLite storage of SAFE AGGREGATE METADATA ONLY: score, class, length, pattern counts, weakness categories.
It never stores the password, a hash of it, or anything reversible. (Even hashes of arbitrary user-submitted
passwords would create a new target and could be attacked offline, so this tool deliberately has none.)"""
from contextlib import contextmanager
import json, os, sqlite3
from collections import Counter
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics.db"))
CLASSES = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"]


@contextmanager
def _conn():
    """Open a connection, commit on success, ALWAYS close (avoids 'unclosed database' warnings)."""
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS analyses (
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT, analyzed_at TEXT, score INTEGER, classification TEXT,
            length INTEGER, pattern_count INTEGER, weaknesses TEXT, patterns TEXT, source TEXT)""")


def record(score: int, classification: str, meta: dict, source: str = "user"):
    with _conn() as c:
        c.execute("INSERT INTO analyses (analyzed_at, score, classification, length, pattern_count, weaknesses, patterns, source)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), score, classification, meta["length"],
                   meta["pattern_count"], json.dumps(meta["weaknesses"]), json.dumps(meta["patterns"]), source))


def clear():
    with _conn() as c:
        c.execute("DELETE FROM analyses")


def stats() -> dict:
    with _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT score, classification, length, weaknesses, patterns FROM analyses")]
    total = len(rows)
    cls = Counter(r["classification"] for r in rows)
    score_b, len_b = [0] * 5, [0] * 5
    weak, pats = Counter(), Counter()
    for r in rows:
        score_b[min(r["score"] // 20, 4)] += 1                       # 0-19, 20-39, ... 80-100
        len_b[0 if r["length"] < 8 else 1 if r["length"] < 12 else 2 if r["length"] < 16 else 3 if r["length"] < 20 else 4] += 1
        weak.update(json.loads(r["weaknesses"] or "[]"))
        pats.update(json.loads(r["patterns"] or "[]"))
    return {"total": total, "classes": {k: cls[k] for k in CLASSES},
            "average_score": round(sum(r["score"] for r in rows) / total, 1) if total else 0,
            "score_buckets": score_b, "length_buckets": len_b,
            "weaknesses": weak.most_common(), "patterns": pats.most_common()}
