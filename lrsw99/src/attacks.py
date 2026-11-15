"""Mutations used to demonstrate failures in credential transfer."""

from dataclasses import replace

from .actors import OrganizationPublicKey
from .credentials import Credential
from .group import GroupParams


def tamper_credential(credential: Credential, field: str, params: GroupParams) -> Credential:
    if field in ("A_prime", "B_prime"):
        changed = getattr(credential, field) * params.g % params.p
    elif field in ("T1", "T2"):
        proof = getattr(credential, field)
        changed = replace(proof, y_prime=(proof.y_prime + 1) % params.q)
    else:
        raise ValueError(f"Unknown credential field: {field}")
    return replace(credential, **{field: changed})


def wrong_issuer_key(key: OrganizationPublicKey, params: GroupParams) -> OrganizationPublicKey:
    # Change h2 within the subgroup and skip the identity.
    h2 = key.h2 * params.g % params.p
    return replace(key, h2=h2 if h2 != 1 else params.g)
