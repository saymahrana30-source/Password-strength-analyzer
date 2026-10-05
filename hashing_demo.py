"""Run:  python hashing_demo.py   (uses ONLY a synthetic demo password)"""
from analyzer.hashing_demo import hash_password, verify_password

demo = "Demo-Only-Passphrase-123"      # synthetic - never use demo passwords for real accounts
h1, h2 = hash_password(demo), hash_password(demo)
print("Stored hash #1:", h1[:70] + "...")
print("Stored hash #2:", h2[:70] + "...")
print("Same password, different salt -> different hashes:", h1 != h2)
print("Verify correct password :", verify_password(demo, h1))
print("Verify wrong password   :", verify_password("wrong-guess", h1))
print("\nHashing is one-way verification. Encryption is reversible with a key - they are not the same thing.")
