"""Interactive Chaum-Pedersen Π and its Fiat–Shamir form Π_NI."""

from dataclasses import dataclass

from .group import GroupParams, hash_to_scalar, inv_mod, modexp, random_scalar


@dataclass(frozen=True)
class PiCommitment:
    A: int
    B: int


@dataclass(frozen=True)
class PiTranscript:
    A: int
    B: int
    c: int
    y: int


def pi_prover_commit(g: int, g_tilde: int, params: GroupParams) -> tuple[PiCommitment, int]:
    r = random_scalar(params.q, nonzero=True)
    return PiCommitment(modexp(g, r, params.p), modexp(g_tilde, r, params.p)), r


def pi_verifier_challenge(params: GroupParams) -> int:
    return random_scalar(params.q, nonzero=True)


def pi_prover_response(r: int, c: int, x: int, q: int) -> int:
    return (r + c * x) % q


def pi_equation_sides(
    g: int, h: int, g_tilde: int, h_tilde: int, transcript: PiTranscript,
    params: GroupParams,
) -> tuple[tuple[int, int], tuple[int, int]]:
    """Evaluate the two verification equations for valid group inputs."""
    A, B, c, y = transcript.A, transcript.B, transcript.c, transcript.y
    p = params.p
    return (
        (modexp(g, y, p), A * modexp(h, c, p) % p),
        (modexp(g_tilde, y, p), B * modexp(h_tilde, c, p) % p),
    )


def pi_verify(
    g: int, h: int, g_tilde: int, h_tilde: int, transcript: PiTranscript,
    params: GroupParams, *, verbose: bool = False,
) -> bool:
    A, B, c, y = transcript.A, transcript.B, transcript.c, transcript.y
    p, q = params.p, params.q
    if verbose:
        print(f"  Statement log_{g}({h}) = log_{g_tilde}({h_tilde})")
        print(f"  A = {A}, B = {B}, c = {c}, y = {y}")

    if not (0 <= c < q and 0 <= y < q) or not all(
        params.contains(value) for value in (g, h, g_tilde, h_tilde, A, B)
    ):
        if verbose:
            print("  Π verified = False (invalid group element or scalar)")
        return False

    (lhs1, rhs1), (lhs2, rhs2) = pi_equation_sides(g, h, g_tilde, h_tilde, transcript, params)
    valid = lhs1 == rhs1 and lhs2 == rhs2
    if verbose:
        print(f"  g^y = {lhs1} | A h^c = {rhs1} (mod {p})")
        print(f"  g_tilde^y = {lhs2} | B h_tilde^c = {rhs2} (mod {p})")
        print(f"  Π verified = {valid}")
    return valid


def run_pi(
    g: int, h: int, g_tilde: int, h_tilde: int, x: int, params: GroupParams,
    *, verbose: bool = False,
) -> tuple[PiTranscript, bool]:
    commitment, r = pi_prover_commit(g, g_tilde, params)
    c = pi_verifier_challenge(params)
    y = pi_prover_response(r, c, x, params.q)
    transcript = PiTranscript(commitment.A, commitment.B, c, y)
    valid = pi_verify(g, h, g_tilde, h_tilde, transcript, params, verbose=verbose)
    return transcript, valid


def extract_witness(c1: int, y1: int, c2: int, y2: int, q: int) -> int:
    # Special soundness: two accepting responses to the same commitment
    # cancel r upon subtraction, giving y1 - y2 = (c1 - c2)*x mod q.
    delta_c = (c1 - c2) % q
    if delta_c == 0:
        raise ValueError("extraction requires distinct challenges modulo q")
    return ((y1 - y2) * inv_mod(delta_c, q)) % q


def prove_pi_ni(g: int, g_tilde: int, x: int, params: GroupParams) -> PiTranscript:
    commitment, r = pi_prover_commit(g, g_tilde, params)
    c = hash_to_scalar(commitment.A, commitment.B, q=params.q)
    return PiTranscript(commitment.A, commitment.B, c, pi_prover_response(r, c, x, params.q))


def verify_pi_ni(
    g: int, h: int, g_tilde: int, h_tilde: int, transcript: PiTranscript,
    params: GroupParams, *, verbose: bool = False,
) -> bool:
    c_hash = hash_to_scalar(transcript.A, transcript.B, q=params.q)
    if verbose:
        print(f"  Fiat–Shamir H(A, B) = {c_hash}, transcript c = {transcript.c}")
    equations_valid = pi_verify(
        g, h, g_tilde, h_tilde, transcript, params, verbose=verbose,
    )
    valid = transcript.c == c_hash and equations_valid
    if verbose:
        print(f"  Π_NI verified = {valid}")
    return valid
