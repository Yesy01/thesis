"""Section 4.2 blinded proof Γ."""

from collections.abc import Callable
from dataclasses import dataclass

from .chaum_pedersen import (
    PiTranscript,
    pi_prover_commit,
    pi_prover_response,
    pi_verify,
    verify_pi_ni,
)
from .group import GroupParams, hash_to_scalar, modexp, random_scalar


@dataclass(frozen=True)
class GammaTranscript:
    A_prime: int
    B_prime: int
    c_hash: int
    y_prime: int


@dataclass(frozen=True)
class GammaTrace:
    interactive: PiTranscript
    alpha: int
    beta: int
    gamma: int
    blinded_valid: bool


def run_gamma(
    g: int, h: int, g_tilde: int, h_tilde: int, x: int, gamma: int,
    params: GroupParams, *, verbose: bool = False,
    on_trace: Callable[[GammaTrace], None] | None = None,
) -> GammaTranscript:
    p, q = params.p, params.q
    if not 0 < gamma < q:
        raise ValueError("gamma must be in Z_q^*")

    # Prover sends the ordinary Π commitment.
    commitment, r = pi_prover_commit(g, g_tilde, params)

    # Verifier blinds it and sends c to the prover.
    alpha = random_scalar(q, nonzero=True)
    beta = random_scalar(q, nonzero=True)
    A_prime = commitment.A * modexp(g, alpha, p) * modexp(h, beta, p) % p
    B_blinded = commitment.B * modexp(g_tilde, alpha, p) * modexp(h_tilde, beta, p) % p
    B_prime = modexp(B_blinded, gamma, p)
    c_hash = hash_to_scalar(A_prime, B_prime, q=q)
    c = (c_hash + beta) % q
    if verbose:
        print(f"  Γ gamma = {gamma}, alpha = {alpha}, beta = {beta}")
        print(f"  A_prime = {A_prime}, B_prime = {B_prime}")
        print(f"  c = (H(A_prime, B_prime) + beta) mod q = {c}")

    # Prover responds as in Π. Verifier checks the original commitment.
    y = pi_prover_response(r, c, x, q)
    transcript = PiTranscript(commitment.A, commitment.B, c, y)
    if not pi_verify(g, h, g_tilde, h_tilde, transcript, params, verbose=verbose):
        raise ValueError("Γ rejected the prover's interactive Π response")

    # A' = A g^alpha h^beta = g^(r + alpha + beta*x) = g^r'.
    # Likewise B' = (g_tilde^gamma)^r', with r' reduced mod q.
    # y' = y + alpha = r + (H(A',B') + beta)*x + alpha
    #    = r' + H(A',B')*x mod q, the response of a fresh Π_NI proof.
    y_prime = (y + alpha) % q
    result = GammaTranscript(A_prime, B_prime, c_hash, y_prime)
    if verbose or on_trace is not None:
        G_tilde = modexp(g_tilde, gamma, p)
        H_tilde = modexp(h_tilde, gamma, p)
    if verbose:
        r_prime = (r + alpha + beta * x) % q
        print(f"  Prover r = {r}")
        print(f"  r_prime = (r + alpha + beta*x) mod q = {r_prime}")
        print(f"  A' = A g^alpha h^beta = g^r' = {A_prime}")
        print(f"  B' = (g_tilde^gamma)^r' = {B_prime}")
        print(f"  y' = y + alpha = r + (H(A',B') + beta)*x + alpha")
        print(f"     = r' + H(A',B')*x mod q = {y_prime}")
        assert A_prime == modexp(g, r_prime, p)
        assert B_prime == modexp(G_tilde, r_prime, p)
        assert y_prime == (r_prime + c_hash * x) % q
    if verbose or on_trace is not None:
        valid = verify_gamma_output(g, h, G_tilde, H_tilde, result, params, verbose=verbose)
        if verbose:
            assert valid
        if on_trace is not None:
            on_trace(GammaTrace(transcript, alpha, beta, gamma, valid))
    return result


def verify_gamma_output(
    g: int, h: int, G_tilde: int, H_tilde: int, transcript: GammaTranscript,
    params: GroupParams, *, verbose: bool = False,
) -> bool:
    """Verify Γ output as Π_NI using the already transformed public pair."""
    proof = PiTranscript(transcript.A_prime, transcript.B_prime, transcript.c_hash, transcript.y_prime)
    return verify_pi_ni(g, h, G_tilde, H_tilde, proof, params, verbose=verbose)
