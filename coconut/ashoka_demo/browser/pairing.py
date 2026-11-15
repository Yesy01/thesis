"""Browser-only subset of petlib/bplib used by the Coconut workshop flow.

The protocol code runs unchanged. This adapter uses BLS12-381 and its
encodings, which differ from the native bplib curve and encodings.
"""

import secrets
import sys
from types import ModuleType

import pairing_browser as native


class Bn(int):
    @staticmethod
    def from_binary(data):
        return Bn(int.from_bytes(data, "big"))

    def __rmod__(self, value):
        return Bn(int(value) % int(self))

    def mod_inverse(self, modulus):
        return Bn(pow(self, -1, modulus))

    def random(self):
        return Bn(secrets.randbelow(self))


ORDER = Bn(int(native.order))


class Point:
    def __init__(self, point):
        self.point = point

    def __add__(self, other):
        return type(self)(self.point.add(other.point))

    def __sub__(self, other):
        return type(self)(self.point.subtract(other.point))

    def __rmul__(self, scalar):
        scalar %= ORDER
        if not scalar:
            return type(self).inf(None)
        return type(self)(native.scale(self.point, str(scalar)))

    def __eq__(self, other):
        return type(self) is type(other) and self.point.equals(other.point)

    def export(self):
        return bytes.fromhex(self.point.toHex())

    def isinf(self):
        return self.point.equals(self.zero)

    @classmethod
    def inf(cls, group):
        return cls(cls.zero)


class G1Elem(Point):
    zero = native.zero1


class G2Elem(Point):
    zero = native.zero2


class PairingResult:
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, PairingResult) and native.equal_pairings(self.value, other.value)


class BpGroup:
    def gen1(self):
        return G1Elem(native.generator1)

    def gen2(self):
        return G2Elem(native.generator2)

    def order(self):
        return ORDER

    def hashG1(self, data):
        return G1Elem(native.hash_to_g1(data.hex()))

    def pair(self, g1, g2):
        return PairingResult(native.pair(g1.point, g2.point))


def install():
    """Register the small compatibility surface inside this Pyodide session."""
    for package, child, exports in (
        ("bplib", "bp", {"BpGroup": BpGroup, "G2Elem": G2Elem}),
        ("petlib", "bn", {"Bn": Bn}),
    ):
        parent = ModuleType(package)
        module = ModuleType(f"{package}.{child}")
        vars(module).update(exports)
        setattr(parent, child, module)
        sys.modules[package] = parent
        sys.modules[module.__name__] = module
