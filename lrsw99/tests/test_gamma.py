from dataclasses import replace

import pytest

from src.gamma import run_gamma, verify_gamma_output
from src.group import DEMO_PARAMS as GROUP, modexp


def test_gamma_output_verifies_for_transformed_statement():
    g, p = GROUP.g, GROUP.p
    x, gamma = 23, 11
    g_tilde = modexp(g, 7, p)
    h, h_tilde = modexp(g, x, p), modexp(g_tilde, x, p)
    G_tilde = modexp(g_tilde, gamma, p)
    H_tilde = modexp(h_tilde, gamma, p)
    proof = run_gamma(g, h, g_tilde, h_tilde, x, gamma, GROUP)
    assert verify_gamma_output(g, h, G_tilde, H_tilde, proof, GROUP)

    tampered = replace(proof, y_prime=(proof.y_prime + 1) % GROUP.q)
    assert not verify_gamma_output(g, h, G_tilde, H_tilde, tampered, GROUP)


@pytest.mark.parametrize("gamma", [0, GROUP.q])
def test_gamma_rejects_invalid_blinding(gamma):
    g = GROUP.g
    with pytest.raises(ValueError, match="gamma"):
        run_gamma(g, g, g, g, 1, gamma, GROUP)
