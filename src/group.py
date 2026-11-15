"""Toy prime-order subgroup arithmetic. INSECURE FOR REAL CRYPTOGRAPHY."""

import hashlib
import json
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class GroupParams:
    """Trusted parameters with p and q prime and g of order q."""

    p: int
    q: int
    g: int

    def contains(self, value: int) -> bool:
        return 1 <= value < self.p and pow(value, self.q, self.p) == 1


# Both p and q are prime, p = 44*q + 1, and g = 2^44 mod p != 1.
DEMO_PARAMS = GroupParams(p=44_000_000_309, q=1_000_000_007, g=36_185_921_125)


def modexp(base: int, exponent: int, p: int) -> int:
    return pow(base, exponent, p)


def inv_mod(x: int, modulus: int) -> int:
    return pow(x, -1, modulus)


def random_scalar(q: int, *, nonzero: bool = False) -> int:
    lower = int(nonzero)
    return lower + secrets.randbelow(q - lower)


def hash_to_scalar(*values: int, q: int) -> int:
    """Hash an ordered sequence of integers using a deterministic encoding."""
    payload = json.dumps(values, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest, "big") % q
