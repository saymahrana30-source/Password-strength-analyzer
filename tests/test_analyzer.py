"""Run with:  python -m unittest discover -s tests -v   (uses SYNTHETIC demo passwords only)"""
import json, os, random, string, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

from analyzer import patterns as pt
from analyzer.engine import analyze_password
from analyzer.scoring import classify, guess_resistance
from analyzer.generator import generate_password, generate_passphrase
from analyzer.hashing_demo import hash_password, verify_password


def cls(pw, ctx=None, pol=None):
    return analyze_password(pw, ctx, pol)["classification"]


class PatternTests(unittest.TestCase):
    def test_common_exact_and_variant(self):
        self.assertEqual(pt.is_common_password("123456")["kind"], "exact")
        self.assertEqual(pt.is_common_password("PASSWORD")["kind"], "exact")
        self.assertEqual(pt.is_common_password("Password123!")["kind"], "variant")
        self.assertEqual(pt.is_common_password("P@ssw0rd")["kind"], "exact")        # listed as-is
        self.assertEqual(pt.is_common_password("P@ssw0rd!")["kind"], "variant")
        self.assertFalse(pt.is_common_password("Xk9#mP2$vL8@nQ4!")["common"])

    def test_sequences(self):
        kinds = lambda p: [(f["kind"], f["direction"]) for f in pt.detect_sequences(p)]
        self.assertEqual(kinds("1234"), [("numeric", "ascending")])
        self.assertEqual(kinds("9876"), [("numeric", "descending")])
        self.assertEqual(kinds("xabcdx"), [("alphabetic", "ascending")])
        self.assertEqual(kinds("dcba"), [("alphabetic", "descending")])
        self.assertEqual(pt.detect_sequences("123"), [])            # too short to flag
        self.assertEqual(pt.detect_sequences("1357"), [])

    def test_keyboard_patterns(self):
        for p in ("qwerty", "asdf", "zxcv", "ytrewq", "QWERTY123", "1qaz2wsx"):
            self.assertTrue(pt.detect_keyboard_patterns(p), p)
        self.assertEqual(pt.detect_keyboard_patterns("Xk9#mP2$"), [])

    def test_repetition(self):
        for p in ("aaaa", "1111", "ababab", "abcabcabc", "AAAAAA123!"):
            self.assertTrue(pt.detect_repetition(p), p)
        self.assertEqual(pt.detect_repetition("Xk9#mP2$vL8@"), [])

    def test_words_years_structure(self):
        self.assertTrue(pt.detect_dictionary_words("welcome123"))
        self.assertTrue(pt.detect_dictionary_words("w3lc0me"))          # leetspeak
        self.assertTrue(pt.detect_years("admin2026"))
        self.assertEqual(pt.detect_years("12026345"), [])               # not a standalone year
        c = pt.is_common_password("bluefrog77")
        self.assertEqual([f["type"] for f in pt.detect_predictable_structure("bluefrog77", c)], ["common_shape"])

    def test_personal_info(self):
        ctx = {"first_name": "Rahul", "birth_year": "2003", "organization": "Sunrise College"}
        fields = lambda p: [h["field"] for h in pt.check_personal_info(p, ctx)]
        self.assertEqual(fields("Rahul@123"), ["first_name"])
        self.assertIn("birth_year", fields("xx2003yy"))
        self.assertIn("organization", fields("Sunrise#99"))
        self.assertEqual(fields("Xk9#mP2$vL8"), [])
        self.assertEqual(pt.check_personal_info("Rahul@123", {}), [])    # no context -> nothing to compare


class ScoringTests(unittest.TestCase):
    def test_brief_demo_cases(self):
        self.assertEqual(cls("123456"), "VERY WEAK")
        self.assertIn(cls("Password123!"), ("WEAK", "MODERATE"))
        self.assertEqual(cls("aaaaaaaaaaaaaaaa"), "WEAK")               # long but repetitive
        self.assertEqual(cls("qwerty2026!"), "WEAK")
        self.assertIn(cls(generate_password(20)), ("STRONG", "VERY STRONG"))

    def test_composition_alone_is_not_strength(self):
        r = analyze_password("Password123!")
        self.assertEqual(r["character_analysis"]["type_count"], 4)
        self.assertLess(r["score"], 41)
        self.assertGreater(r["entropy"]["theoretical_bits"], r["entropy"]["effective_bits"] * 3)

    def test_personal_info_lowers_score(self):
        self.assertLess(analyze_password("Rahul@123", {"first_name": "Rahul"})["score"], 41)

    def test_very_short_is_capped(self):
        self.assertLessEqual(analyze_password("a")["score"], 15)
        self.assertLessEqual(analyze_password("aB3$x7!")["score"], 35)

    def test_longer_random_scores_higher(self):
        avg = lambda n: sum(analyze_password(generate_password(n))["score"] for _ in range(60)) / 60
        self.assertLess(avg(8), avg(12) + 1)
        self.assertLess(avg(12), avg(20) + 1)

    def test_passphrases_improve_with_more_words(self):
        score = lambda n: sum(analyze_password(generate_passphrase(n)["passphrase"])["score"] for _ in range(30)) / 30
        self.assertLess(score(3), score(5))

    def test_random_passwords_rarely_flagged(self):
        low = [1 for _ in range(500) if analyze_password(generate_password(16))["score"] < 70]
        self.assertEqual(len(low), 0)

    def test_classification_boundaries(self):
        self.assertEqual([classify(s) for s in (0, 20, 21, 40, 41, 60, 61, 80, 81, 100)],
                         ["VERY WEAK", "VERY WEAK", "WEAK", "WEAK", "MODERATE", "MODERATE", "STRONG", "STRONG", "VERY STRONG", "VERY STRONG"])

    def test_score_always_bounded_fuzz(self):
        rng = random.Random(7)
        alphabet = string.printable[:94] + " éü中"
        for _ in range(1500):
            pw = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 90)))
            self.assertTrue(0 <= analyze_password(pw, {"first_name": "abc"})["score"] <= 100)

    def test_guess_resistance_is_coarse_and_labelled(self):
        g = guess_resistance(40)
        self.assertEqual(g["label"], "Educational estimate only")
        allowed = {"under a minute", "minutes", "hours", "days to months", "years to centuries", "far beyond practical limits"}
        self.assertTrue(all(s["estimate"] in allowed for s in g["scenarios"]))
        self.assertIn("attacker model", g["caveat"])


class PolicyTests(unittest.TestCase):
    def test_policy_differs_from_strength(self):
        r = analyze_password("Password123!", None, {"common_password_check": False, "minimum_length": 12})
        self.assertEqual(r["policy"]["result"], "POLICY PASS")           # passes this policy ...
        self.assertLess(r["score"], 41)                                   # ... yet is still weak

    def test_policy_failures(self):
        self.assertEqual(analyze_password("short")["policy"]["result"], "POLICY FAIL")
        self.assertEqual(analyze_password("password1234")["policy"]["result"], "POLICY FAIL")   # common password
        r = analyze_password("123456789012")      # long enough and not on the list ...
        self.assertEqual(r["policy"]["result"], "POLICY PASS")
        self.assertIn(r["classification"], ("VERY WEAK", "WEAK"))   # ... but still a predictable sequence
        self.assertEqual(analyze_password("Xk9#mP2$vL8@nQ4!")["policy"]["result"], "POLICY PASS")
        r = analyze_password("Xk9#mP2$vL8@nQ4!", None, {"allow_spaces": False, "maximum_length": 10})
        self.assertEqual(r["policy"]["result"], "POLICY FAIL")


class GeneratorTests(unittest.TestCase):
    def test_lengths_and_classes(self):
        for n in (16, 20, 24):
            pw = generate_password(n)
            self.assertEqual(len(pw), n)
            self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                            and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw))
        self.assertTrue(generate_password(16, symbols=False, numbers=False).isalpha())

    def test_uniqueness_and_validation(self):
        self.assertEqual(len({generate_password(20) for _ in range(200)}), 200)
        for bad in (dict(length=4), dict(length=100), dict(uppercase=False, lowercase=False, numbers=False, symbols=False)):
            with self.assertRaises(ValueError):
                generate_password(**{"length": 20, **bad})

    def test_uses_secrets_not_random(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "analyzer", "generator.py")).read()
        self.assertIn("import math, os, secrets", src)
        self.assertNotIn("import random", src)

    def test_passphrase(self):
        p = generate_passphrase(5)
        self.assertEqual(len(p["passphrase"].split("-")), 5)
        self.assertGreaterEqual(p["wordlist_size"], 256)
        with self.assertRaises(ValueError):
            generate_passphrase(1)


class HashingDemoTests(unittest.TestCase):
    def test_salted_and_verifiable(self):
        h1, h2 = hash_password("Demo-Only-123"), hash_password("Demo-Only-123")
        self.assertNotEqual(h1, h2)                                       # unique salt each time
        self.assertTrue(verify_password("Demo-Only-123", h1))
        self.assertFalse(verify_password("wrong", h1))
        self.assertNotIn("Demo-Only-123", h1)
        self.assertFalse(verify_password("x", "not-a-valid-hash"))


class PrivacyAndApiTests(unittest.TestCase):
    PW = "Zebra#Quokka99"      # synthetic and not quoted by any static advice text

    def setUp(self):
        import app as appmod, db
        self.app, self.db = appmod, db
        db.clear()
        appmod.reset_rate_limit()
        appmod.app.config["RATE_LIMIT_PER_MIN"] = 300
        self.c = appmod.app.test_client()

    def post(self, **kw):
        return self.c.post("/api/analyze", json=kw)

    def test_response_never_echoes_password(self):
        for pw, ctx in ((self.PW, None), ("Rahul@123", {"first_name": "Rahul"})):
            body = json.dumps(self.post(password=pw, context=ctx or {}).get_json())
            for i in range(len(pw) - 4):
                self.assertNotIn(pw[i:i + 5], body, "response leaked part of the password")

    def test_database_stores_no_password(self):
        r = self.post(password=self.PW, record=True).get_json()
        self.assertTrue(r["recorded"])
        raw = open(self.db.DB_PATH, "rb").read()
        self.assertNotIn(b"Zebra", raw); self.assertNotIn(b"Quokka", raw)
        import sqlite3, contextlib
        with contextlib.closing(sqlite3.connect(self.db.DB_PATH)) as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(analyses)")}
        self.assertEqual(cols, {"analysis_id", "analyzed_at", "score", "classification", "length", "pattern_count",
                                "weaknesses", "patterns", "source"})

    def test_not_recorded_by_default(self):
        self.post(password=self.PW)
        self.assertEqual(self.c.get("/api/dashboard/stats").get_json()["total"], 0)

    def test_errors_do_not_leak_or_log_password(self):
        with mock.patch("app.analyze_password", side_effect=RuntimeError("leak-" + self.PW)):
            with self.assertLogs(self.app.app.logger, level="ERROR") as cm:
                r = self.post(password=self.PW)
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("Zebra", r.get_data(as_text=True))
        self.assertNotIn("Zebra", "\n".join(cm.output))

    def test_validation_errors_are_generic(self):
        for body in ({}, {"password": ""}, {"password": 12345}, {"password": "x" * 257}, {"password": None}):
            r = self.post(**body)
            self.assertEqual(r.status_code, 400)
            self.assertNotIn("xxxx", r.get_data(as_text=True))
        self.assertEqual(self.c.post("/api/analyze", data="not json", content_type="text/plain").status_code, 400)

    def test_oversized_request_rejected(self):
        self.assertEqual(self.c.post("/api/analyze", json={"password": "a", "pad": "x" * 20000}).status_code, 413)

    def test_no_store_header_and_security_headers(self):
        r = self.post(password=self.PW)
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_rate_limiting(self):
        self.app.app.config["RATE_LIMIT_PER_MIN"] = 3
        codes = [self.post(password="abc").status_code for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    def test_analyze_response_shape(self):
        r = self.post(password="Password123!").get_json()
        for key in ("score", "classification", "findings", "suggestions", "policy", "entropy", "guess_resistance", "disclaimer"):
            self.assertIn(key, r)
        self.assertNotIn("_meta", r)

    def test_policy_input_is_sanitised(self):
        r = self.post(password="abc", policy={"minimum_length": "DROP TABLE", "common_password_check": "yes"}).get_json()
        self.assertEqual(r["policy"]["checks"][0]["message"], "At least 12 characters required.")

    def test_dashboard_and_weaknesses(self):
        self.assertEqual(self.c.post("/api/demo-seed").status_code, 200)
        s = self.c.get("/api/dashboard/stats").get_json()
        self.assertGreater(s["total"], 20)
        self.assertEqual(sum(s["classes"].values()), s["total"])
        self.assertEqual(sum(s["score_buckets"]), s["total"])
        w = self.c.get("/api/analytics/weaknesses").get_json()
        self.assertTrue(w["weaknesses"] and w["patterns"])
        self.c.delete("/api/history")
        self.assertEqual(self.c.get("/api/dashboard/stats").get_json()["total"], 0)

    def test_generator_endpoints(self):
        r = self.c.post("/api/generate-password", json={"length": 24}).get_json()
        self.assertEqual(len(r["password"]), 24)
        self.assertEqual(self.c.post("/api/generate-password", json={"length": 3}).status_code, 400)
        self.assertEqual(self.c.post("/api/generate-password", json={"uppercase": False, "lowercase": False, "numbers": False, "symbols": False}).status_code, 400)
        self.assertEqual(len(self.c.post("/api/generate-passphrase", json={"words": 6}).get_json()["passphrase"].split("-")), 6)
        self.assertEqual(self.c.post("/api/generate-passphrase", json={"words": 99}).status_code, 400)

    def test_not_found_is_json(self):
        r = self.c.get("/api/nope")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())


if __name__ == "__main__":
    unittest.main()
