"""Section 4.3 credential issuance and transfer."""

from collections.abc import Callable
from dataclasses import dataclass

from .actors import Organization, OrganizationPublicKey, User
from .chaum_pedersen import PiTranscript, run_pi
from .gamma import GammaTrace, GammaTranscript, run_gamma, verify_gamma_output
from .group import GroupParams, modexp, random_scalar
from .pseudonym import Pseudonym


@dataclass(frozen=True)
class Credential:
    """One-time credential. Reusing this tuple can link presentations."""

    a_prime: int
    b_prime: int
    A_prime: int
    B_prime: int
    T1: GammaTranscript
    T2: GammaTranscript


@dataclass(frozen=True)
class IssuanceTrace:
    A: int
    B: int
    T1: GammaTrace
    T2: GammaTrace


@dataclass(frozen=True)
class TransferResult:
    transcript_1_valid: bool
    transcript_2_valid: bool
    ownership_proof_valid: bool

    @property
    def accepted(self) -> bool:
        return self.transcript_1_valid and self.transcript_2_valid and self.ownership_proof_valid


def issue_credential(
    organization: Organization, pseudonym: Pseudonym, params: GroupParams, *,
    verbose: bool = False, on_trace: Callable[[IssuanceTrace], None] | None = None,
) -> Credential:
    """Simulate issuance for a pseudonym the issuer has already authenticated."""
    if not pseudonym.is_valid(params):
        raise ValueError("invalid issuer pseudonym")

    p, q, g = params.p, params.q, params.g
    a, b = pseudonym.a, pseudonym.b
    key = organization.credential_key
    # The issuer sends A and B to the user.
    A = modexp(b, key.s2, p)
    aA = a * A % p
    B = modexp(aA, key.s1, p)

    # The user transforms both statements with one gamma so they certify
    # the same tuple: (a*A)^gamma = a^gamma * A^gamma mod p.
    gamma = random_scalar(q, nonzero=True)
    if verbose:
        print(f"  Issuer sends A = b^s2 = {A}, B = (a*A)^s1 = {B}")
        print(f"  User chooses gamma = {gamma}")
        print("  Γ for T1 proving log_g(h2) = log_b(A)")
    traces: list[GammaTrace] = []
    capture = traces.append if on_trace is not None else None
    T1 = run_gamma(g, key.h2, b, A, key.s2, gamma, params, verbose=verbose, on_trace=capture)
    if verbose:
        print("  Γ for T2 proving log_g(h1) = log_(a*A)(B)")
    T2 = run_gamma(g, key.h1, aA, B, key.s1, gamma, params, verbose=verbose, on_trace=capture)
    if on_trace is not None:
        on_trace(IssuanceTrace(A, B, *traces))

    credential = Credential(
        modexp(a, gamma, p), modexp(b, gamma, p),
        modexp(A, gamma, p), modexp(B, gamma, p), T1, T2,
    )
    if verbose:
        print(f"  T1 = {T1}")
        print(f"  T2 = {T2}")
        print(f"  Credential = {credential}")
        assert credential.A_prime == modexp(credential.b_prime, key.s2, p)
        assert credential.B_prime == modexp(credential.a_prime * credential.A_prime % p, key.s1, p)
    return credential


def transfer_credential(
    user: User, credential: Credential, issuer_public_key: OrganizationPublicKey,
    receiving_pseudonym: Pseudonym, params: GroupParams, *, verbose: bool = False,
    on_ownership_proof: Callable[[PiTranscript], None] | None = None,
) -> TransferResult:
    p, g = params.p, params.g
    a, b = credential.a_prime, credential.b_prime
    A, B = credential.A_prime, credential.B_prime

    if verbose:
        print("  Receiving organization verifies T1")
    t1_valid = verify_gamma_output(
        g, issuer_public_key.h2, b, A, credential.T1, params, verbose=verbose,
    )
    if verbose:
        print("  Receiving organization verifies T2")
    # a*A may equal 1 for valid inputs. In that case T2 checks B = 1
    # (for a nonzero hash challenge) and still proves knowledge of log_g(h1).
    t2_valid = params.contains(a) and params.contains(A) and verify_gamma_output(
        g, issuer_public_key.h1, a * A % p, B, credential.T2, params, verbose=verbose,
    )

    issuer_key_valid = all(
        value != 1 and params.contains(value)
        for value in (issuer_public_key.h1, issuer_public_key.h2)
    )
    if not (
        t1_valid and t2_valid and A != 1
        and Pseudonym(a, b).is_valid(params) and receiving_pseudonym.is_valid(params)
        and issuer_key_valid
    ):
        return TransferResult(t1_valid, t2_valid, False)

    if verbose:
        print("  User proves ownership across the receiving and credential pseudonyms")
    proof, ownership_valid = run_pi(
        receiving_pseudonym.a, receiving_pseudonym.b, a, b, user.master_secret,
        params, verbose=verbose,
    )
    if on_ownership_proof is not None:
        on_ownership_proof(proof)
    return TransferResult(t1_valid, t2_valid, ownership_valid)
