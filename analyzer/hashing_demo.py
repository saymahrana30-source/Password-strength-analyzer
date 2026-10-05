"""SEPARATE educational demo of safe password STORAGE. It is NOT used by the analyzer or the web app:
arbitrary passwords typed into the analyzer are never hashed or stored.
Password -> random salt -> slow password-hashing function -> stored string. Hashing is one-way;
encryption is reversible with a key. Never store passwords with plain MD5/SHA-1/SHA-256."""
import base64, hashlib, hmac, os

N, R, P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)                                          # unique salt per password
    dk = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=32)
    return "scrypt${}${}${}${}${}".format(N, R, P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, expected = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(expected))     # constant-time comparison
    except (ValueError, TypeError):
        return False
