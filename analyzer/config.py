"""All tunable settings. Scores, bands and penalties are PROJECT-DEFINED, not universal standards."""

CLASS_BANDS = [(20, "VERY WEAK"), (40, "WEAK"), (60, "MODERATE"), (80, "STRONG"), (100, "VERY STRONG")]
LENGTH_BANDS = [(8, "Very short"), (12, "Short"), (16, "Better length"), (10**9, "Strong length contribution")]

# Maximum points per component (they add up to 100)
MAX_POINTS = {"length": 35, "diversity": 15, "unique_ratio": 10, "pattern_resistance": 20,
              "non_common": 10, "unpredictability": 10}

# Penalties: (points per finding, maximum total for that finding type)
PENALTIES = {"common_exact": (40, 40), "common_variant": (10, 10), "keyboard": (8, 16), "sequence": (6, 12),
             "repetition": (8, 16), "personal": (20, 40), "common_word": (6, 6), "year": (5, 5),
             "word_plus_number": (8, 8), "common_shape": (4, 4)}

# Score can never exceed a cap that depends on the pattern-aware effective entropy (bits)
ENTROPY_CAPS = [(30, 30), (45, 50), (60, 60)]   # (effective bits below, max score)
LENGTH_CAPS = [(6, 15), (8, 35)]                  # (length below, max score)
COMMON_EXACT_CAP, COMMON_VARIANT_CAP = 15, 40

# Rough "bits of guessing work" assigned to each recognised pattern (a human-chosen pattern is far
# cheaper to guess than random characters). Heuristic values for teaching, not measurements.
PATTERN_BITS = {"sequence": 8, "keyboard": 8, "repetition": 4, "common_word": 10, "year": 7, "personal": 4,
                "word_plus_number": 8, "common_shape": 24}

POOL_SIZES = {"lowercase": 26, "uppercase": 26, "numbers": 10, "symbols": 32, "spaces": 1, "unicode": 64}

MIN_SEQUENCE, MIN_KEYBOARD, MIN_WORD = 4, 4, 4
MAX_PASSWORD_LEN = 256

DEFAULT_POLICY = {"minimum_length": 12, "maximum_length": 128, "common_password_check": True,
                  "personal_info_check": True, "allow_spaces": True}

# Educational guess-rate ASSUMPTIONS (guesses per second). Real values vary enormously.
GUESS_SCENARIOS = [
    ("Online, rate-limited login", 10, "about 10 guesses/second"),
    ("Offline, slow password hash (scrypt/bcrypt/Argon2)", 10_000, "about 10,000 guesses/second"),
    ("Offline, fast unsalted hash", 10_000_000_000, "about 10 billion guesses/second"),
]
