from dataclasses import replace

import pytest

from src.actors import MasterKey, Organization, OrganizationCredentialKey, User
from src.credentials import TransferResult, issue_credential, transfer_credential
from src.group import DEMO_PARAMS as GROUP, modexp
from src.pseudonym import Pseudonym, generate_pseudonym


@pytest.fixture
def presentation(monkeypatch):
    g, p = GROUP.g, GROUP.p
    alice = User(MasterKey(3, modexp(g, 3, p)))
    bob = User(MasterKey(5, modexp(g, 5, p)))
    issuer = Organization(OrganizationCredentialKey(47, 53, modexp(g, 47, p), modexp(g, 53, p)))
    receiver = Organization.generate(GROUP)

    # Fix the draws that feed into Γ to make its hash challenges reproducible.
    registration = iter((59, 61, 67, 71, 73, 79))
    with monkeypatch.context() as setup:
        setup.setattr("src.pseudonym.random_scalar", lambda q, *, nonzero: next(registration))
        nym, _, _ = generate_pseudonym(alice, issuer, GROUP)
        alice_receiving, _, _ = generate_pseudonym(alice, receiver, GROUP)
        bob_receiving, _, _ = generate_pseudonym(bob, receiver, GROUP)

        nonces = iter((29, 31))
        blinding = iter((37, 41, 43, 47))
        setup.setattr("src.chaum_pedersen.random_scalar", lambda q, *, nonzero: next(nonces))
        setup.setattr("src.gamma.random_scalar", lambda q, *, nonzero: next(blinding))
        setup.setattr("src.credentials.random_scalar", lambda q, *, nonzero: 53)
        credential = issue_credential(issuer, nym, GROUP)

    return alice, bob, issuer.public_key, alice_receiving, bob_receiving, credential


def test_honest_transfer(presentation):
    alice, _, key, nym, _, credential = presentation
    result = transfer_credential(alice, credential, key, nym, GROUP)
    assert result == TransferResult(True, True, True)
    assert result.accepted


def test_wrong_master_secret(presentation):
    _, bob, key, nym, _, credential = presentation
    result = transfer_credential(bob, credential, key, nym, GROUP)
    assert result == TransferResult(True, True, False)
    assert not result.accepted


def test_different_users_pseudonym(presentation):
    alice, _, key, _, nym, credential = presentation
    result = transfer_credential(alice, credential, key, nym, GROUP)
    assert result == TransferResult(True, True, False)
    assert not result.accepted


@pytest.mark.parametrize(
    ("field", "first_valid", "second_valid"),
    [("A_prime", False, False), ("B_prime", True, False), ("T1", False, True), ("T2", True, False)],
)
def test_tampered_credential(presentation, field, first_valid, second_valid):
    alice, _, key, nym, _, credential = presentation
    value = getattr(credential, field)
    if field in ("T1", "T2"):
        value = replace(value, y_prime=(value.y_prime + 1) % GROUP.q)
    else:
        value = value * GROUP.g % GROUP.p
    result = transfer_credential(alice, replace(credential, **{field: value}), key, nym, GROUP)
    assert result == TransferResult(first_valid, second_valid, False)
    assert not result.accepted


def test_wrong_issuer_public_key(presentation):
    alice, _, key, nym, _, credential = presentation
    wrong_key = replace(key, h2=key.h2 * GROUP.g % GROUP.p)
    result = transfer_credential(alice, credential, wrong_key, nym, GROUP)
    assert result == TransferResult(False, True, False)
    assert not result.accepted


def test_issuance_when_second_base_is_identity():
    g, p, q = GROUP.g, GROUP.p, GROUP.q
    user = User(MasterKey(1, g))
    issuer = Organization(OrganizationCredentialKey(1, q - 1, g, modexp(g, q - 1, p)))
    nym = Pseudonym(g, g)
    credential = issue_credential(issuer, nym, GROUP)
    assert credential.a_prime * credential.A_prime % p == credential.B_prime == 1
    assert transfer_credential(user, credential, issuer.public_key, nym, GROUP).accepted
