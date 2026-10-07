"""Negative tests for the original Coconut API's failure behavior."""

from types import SimpleNamespace

import pytest

from coconut.scheme import (
    agg_cred,
    agg_key,
    blind_sign,
    prepare_blind_sign,
    prove_cred,
    setup,
    ttp_keygen,
    unblind,
    verify_cred,
)
from coconut.utils import elgamal_keygen


def rejected(params, verification_key, theta):
    """Normalize false returns and proof assertions to one rejection result."""
    try:
        return not verify_cred(params, verification_key, theta)
    except AssertionError:
        return True


@pytest.fixture
def issued_credential():
    params = setup(1)
    private_m = [42]
    secret_keys, verification_keys = ttp_keygen(params, 2, 3)
    aggregate_vk = agg_key(
        params, [verification_keys[0], verification_keys[1], None]
    )
    elgamal_private, gamma = elgamal_keygen(params)
    request = prepare_blind_sign(params, gamma, private_m)
    blinded = [
        blind_sign(params, secret_keys[i], gamma, request)
        for i in range(2)
    ]
    shares = [unblind(params, item, elgamal_private) for item in blinded]
    sigma = agg_cred(params, [shares[0], shares[1], None])
    theta = prove_cred(params, aggregate_vk, sigma, private_m)
    assert verify_cred(params, aggregate_vk, theta)
    return SimpleNamespace(
        params=params,
        private_m=private_m,
        secret_keys=secret_keys,
        verification_keys=verification_keys,
        aggregate_vk=aggregate_vk,
        shares=shares,
        sigma=sigma,
        theta=theta,
    )


def test_changed_private_attribute_is_rejected(issued_credential):
    flow = issued_credential
    wrong_attribute = [flow.private_m[0] + 1]
    wrong_theta = prove_cred(
        flow.params, flow.aggregate_vk, flow.sigma, wrong_attribute
    )
    assert rejected(flow.params, flow.aggregate_vk, wrong_theta)


def test_fewer_than_threshold_shares_fail_against_threshold_key(
    issued_credential,
):
    flow = issued_credential
    # The original interpolation helper fails early for a one-element index
    # set because its denominator remains a Python int. Preserve that behavior
    # and separately demonstrate that one partial credential cannot verify
    # against the consolidated two-authority verification key.
    with pytest.raises(AttributeError, match="mod_inverse"):
        agg_cred(flow.params, [flow.shares[0], None, None])
    one_share_sigma = flow.shares[0]
    one_share_theta = prove_cred(
        flow.params,
        flow.aggregate_vk,
        one_share_sigma,
        flow.private_m,
    )
    assert rejected(flow.params, flow.aggregate_vk, one_share_theta)


def test_corrupted_credential_share_is_rejected(issued_credential):
    flow = issued_credential
    _, _, g1, _, _, _ = flow.params
    share_h, share_s = flow.shares[1]
    corrupted_share = (share_h, share_s + g1)
    corrupted_sigma = agg_cred(
        flow.params, [flow.shares[0], corrupted_share, None]
    )
    corrupted_theta = prove_cred(
        flow.params,
        flow.aggregate_vk,
        corrupted_sigma,
        flow.private_m,
    )
    assert rejected(flow.params, flow.aggregate_vk, corrupted_theta)


def test_malformed_showing_proof_is_rejected(issued_credential):
    flow = issued_credential
    _, order, _, _, _, _ = flow.params
    kappa, nu, sigma_prime, proof = flow.theta
    challenge, responses_m, response_t = proof
    malformed_proof = (
        (challenge + 1) % order,
        responses_m,
        response_t,
    )
    malformed_theta = (kappa, nu, sigma_prime, malformed_proof)
    assert rejected(flow.params, flow.aggregate_vk, malformed_theta)


def test_wrong_verification_key_is_rejected(issued_credential):
    flow = issued_credential
    _, wrong_verification_keys = ttp_keygen(flow.params, 2, 3)
    wrong_aggregate_vk = agg_key(
        flow.params,
        [wrong_verification_keys[0], wrong_verification_keys[1], None],
    )
    assert rejected(flow.params, wrong_aggregate_vk, flow.theta)


def test_independently_altered_randomized_component_is_rejected(
    issued_credential,
):
    flow = issued_credential
    _, _, g1, _, _, _ = flow.params
    kappa, nu, sigma_prime, proof = flow.theta
    h_prime, s_prime = sigma_prime
    altered_sigma_prime = (h_prime + g1, s_prime)
    altered_theta = (kappa, nu, altered_sigma_prime, proof)
    assert rejected(flow.params, flow.aggregate_vk, altered_theta)
