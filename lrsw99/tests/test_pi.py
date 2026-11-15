from dataclasses import replace
from math import isqrt

import pytest

from src.chaum_pedersen import (
    PiTranscript,
    extract_witness,
    pi_prover_commit,
    pi_prover_response,
    pi_verify,
    prove_pi_ni,
    run_pi,
    verify_pi_ni,
)
from src.group import DEMO_PARAMS as GROUP, hash_to_scalar, modexp


def statement(x):
    g, p = GROUP.g, GROUP.p
    g_tilde = modexp(g, 7, p)
    return g, modexp(g, x, p), g_tilde, modexp(g_tilde, x, p)


def test_demo_group():
    p, q, g = GROUP.p, GROUP.q, GROUP.g
    assert all(n % d for n in (p, q) for d in range(2, isqrt(n) + 1))
    assert p - 1 == 44 * q
    assert g == modexp(2, 44, p)
    assert g != 1 and GROUP.contains(g)


@pytest.mark.parametrize("x", [1, 23, GROUP.q - 1])
def test_pi_completeness(x):
    public = statement(x)
    transcript, accepted = run_pi(*public, x, GROUP)
    assert accepted
    assert pi_verify(*public, transcript, GROUP)


def test_pi_rejects_false_relation():
    g, h, g_tilde, _ = statement(23)
    h_tilde = modexp(g_tilde, 24, GROUP.p)
    _, accepted = run_pi(g, h, g_tilde, h_tilde, 23, GROUP)
    assert not accepted


def test_extract_witness():
    x = 23
    g, h, g_tilde, h_tilde = statement(x)
    commitment, r = pi_prover_commit(g, g_tilde, GROUP)
    c1, c2 = 3, 11
    y1 = pi_prover_response(r, c1, x, GROUP.q)
    y2 = pi_prover_response(r, c2, x, GROUP.q)
    for c, y in ((c1, y1), (c2, y2)):
        proof = PiTranscript(commitment.A, commitment.B, c, y)
        assert pi_verify(g, h, g_tilde, h_tilde, proof, GROUP)
    assert extract_witness(c1, y1, c2, y2, GROUP.q) == x
    with pytest.raises(ValueError, match="distinct challenges"):
        extract_witness(c1, y1, c1 + GROUP.q, y1, GROUP.q)


def test_pi_ni_checks_hash_and_equations():
    x = 23
    g, h, g_tilde, h_tilde = statement(x)
    proof = prove_pi_ni(g, g_tilde, x, GROUP)
    assert proof.c == hash_to_scalar(proof.A, proof.B, q=GROUP.q)
    assert verify_pi_ni(g, h, g_tilde, h_tilde, proof, GROUP)

    bad_response = replace(proof, y=(proof.y + 1) % GROUP.q)
    assert not verify_pi_ni(g, h, g_tilde, h_tilde, bad_response, GROUP)

    # Change both c and y so the interactive equations still hold.
    bad_hash = replace(proof, c=(proof.c + 1) % GROUP.q, y=(proof.y + x) % GROUP.q)
    assert pi_verify(g, h, g_tilde, h_tilde, bad_hash, GROUP)
    assert not verify_pi_ni(g, h, g_tilde, h_tilde, bad_hash, GROUP)
