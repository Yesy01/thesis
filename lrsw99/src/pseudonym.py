"""Pseudonym registration and authentication from Section 4.3."""

from dataclasses import dataclass

from .actors import Organization, User
from .chaum_pedersen import PiTranscript, run_pi
from .group import GroupParams, modexp, random_scalar


@dataclass(frozen=True)
class Pseudonym:
    a: int
    b: int

    def is_valid(self, params: GroupParams) -> bool:
        return all(value != 1 and params.contains(value) for value in (self.a, self.b))


@dataclass(frozen=True)
class PseudonymTrace:
    gamma: int
    a_tilde: int
    b_tilde: int
    r: int


def generate_pseudonym(
    user: User, organization: Organization, params: GroupParams, *, verbose: bool = False, capture_trace: bool = False,
) -> tuple[Pseudonym, PiTranscript, PseudonymTrace | None]:
    # Ordinary organizations receive a randomized initial pair. The CA
    # deliberately receives the master public key via (g, g^x).
    x = user.master_secret
    gamma = 1 if organization.is_ca else random_scalar(params.q, nonzero=True)
    a_tilde = modexp(params.g, gamma, params.p)
    b_tilde = user.master_public if organization.is_ca else modexp(a_tilde, x, params.p)

    # The organization chooses r and returns only a to the user.
    r = random_scalar(params.q, nonzero=True)
    a = modexp(a_tilde, r, params.p)
    b = modexp(a, x, params.p)
    pseudonym = Pseudonym(a, b)
    trace = PseudonymTrace(gamma, a_tilde, b_tilde, r) if capture_trace or verbose else None
    if verbose:
        print(f"  x = {x}, gamma = {gamma}, organization r = {r}")
        print(f"  a_tilde = {a_tilde}, b_tilde = {b_tilde}")
        print(f"  a = {a}, b = {b}")
        assert b == modexp(b_tilde, r, params.p)
    if not pseudonym.is_valid(params) or not Pseudonym(a_tilde, b_tilde).is_valid(params):
        raise ValueError("invalid pseudonym group elements")
    proof, valid = run_pi(a, b, a_tilde, b_tilde, x, params, verbose=verbose)
    if not valid:
        raise ValueError("pseudonym registration proof failed")
    return pseudonym, proof, trace


def authenticate_pseudonym(
    user: User, pseudonym: Pseudonym, params: GroupParams, *, verbose: bool = False,
) -> bool:
    if not pseudonym.is_valid(params):
        return False
    a, b = pseudonym.a, pseudonym.b
    _, valid = run_pi(a, b, a, b, user.master_secret, params, verbose=verbose)
    return valid
