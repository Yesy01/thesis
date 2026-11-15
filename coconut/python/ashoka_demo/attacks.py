"""Controlled negative experiments against the original Coconut verifier."""

from types import SimpleNamespace

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


ATTACKS = (
    {
        "id": "changed_attribute",
        "title": "Change the private attribute",
        "assumption": "A showing must remain bound to the attributes signed during issuance.",
        "mutation": "Create the showing with k + 1 while keeping the original credential.",
    },
    {
        "id": "insufficient_shares",
        "title": "Use one authority share",
        "assumption": "One share must not verify against a 2-of-3 aggregate verification key.",
        "mutation": "Use authority 1's partial credential without a second share.",
    },
    {
        "id": "corrupted_share",
        "title": "Corrupt a credential share",
        "assumption": "Changing a partial credential must invalidate the aggregated credential.",
        "mutation": "Add the G1 generator to authority 2's signature component before aggregation.",
    },
    {
        "id": "malformed_proof",
        "title": "Alter the showing proof",
        "assumption": "A modified Fiat-Shamir challenge must be rejected.",
        "mutation": "Increment the pi_v challenge while leaving its responses unchanged.",
    },
    {
        "id": "wrong_verification_key",
        "title": "Use a different issuer key",
        "assumption": "A credential must verify only under the matching aggregate verification key.",
        "mutation": "Verify under a newly generated, unrelated 2-of-3 key.",
    },
    {
        "id": "altered_randomized_credential",
        "title": "Alter the randomized credential",
        "assumption": "The showing proof and pairing equation must bind the randomized credential.",
        "mutation": "Add the G1 generator to h' without updating the proof.",
    },
)


def list_attacks():
    return [dict(item) for item in ATTACKS]


def _issued_context():
    params = setup(2)
    _, order, _, _, _, _ = params
    private_attributes = [order.random()]
    public_attributes = [20261007]
    secret_keys, verification_keys = ttp_keygen(params, 2, 3)
    aggregate_vk = agg_key(
        params, [verification_keys[0], verification_keys[1], None]
    )
    elgamal_private, gamma = elgamal_keygen(params)
    request = prepare_blind_sign(
        params, gamma, private_attributes, public_m=public_attributes
    )
    blinded = [
        blind_sign(
            params,
            secret_keys[index],
            gamma,
            request,
            public_m=public_attributes,
        )
        for index in range(2)
    ]
    shares = [
        unblind(params, blinded_share, elgamal_private)
        for blinded_share in blinded
    ]
    credential = agg_cred(params, [shares[0], shares[1], None])
    theta = prove_cred(params, aggregate_vk, credential, private_attributes)
    assert verify_cred(
        params, aggregate_vk, theta, public_m=public_attributes
    )
    return SimpleNamespace(
        params=params,
        private_attributes=private_attributes,
        public_attributes=public_attributes,
        verification_keys=verification_keys,
        aggregate_vk=aggregate_vk,
        shares=shares,
        credential=credential,
        theta=theta,
    )


def _observe_verification(context, verification_key, theta):
    try:
        accepted = verify_cred(
            context.params,
            verification_key,
            theta,
            public_m=context.public_attributes,
        )
    except AssertionError:
        return False, "verify_cred raised AssertionError"
    return accepted, "verify_cred returned {}".format(accepted)


def run_attack(attack_id):
    metadata = next((item for item in ATTACKS if item["id"] == attack_id), None)
    if metadata is None:
        raise ValueError("unknown attack experiment")

    context = _issued_context()
    verification_key = context.aggregate_vk
    note = None

    if attack_id == "changed_attribute":
        wrong_attribute = [context.private_attributes[0] + 1]
        theta = prove_cred(
            context.params,
            context.aggregate_vk,
            context.credential,
            wrong_attribute,
        )
    elif attack_id == "insufficient_shares":
        try:
            agg_cred(context.params, [context.shares[0], None, None])
        except AttributeError as error:
            note = "The original one-share interpolation path raises {}.".format(
                type(error).__name__
            )
        theta = prove_cred(
            context.params,
            context.aggregate_vk,
            context.shares[0],
            context.private_attributes,
        )
    elif attack_id == "corrupted_share":
        _, _, g1, _, _, _ = context.params
        share_h, share_s = context.shares[1]
        corrupted = (share_h, share_s + g1)
        credential = agg_cred(
            context.params, [context.shares[0], corrupted, None]
        )
        theta = prove_cred(
            context.params,
            context.aggregate_vk,
            credential,
            context.private_attributes,
        )
    elif attack_id == "malformed_proof":
        _, order, _, _, _, _ = context.params
        kappa, nu, sigma_prime, proof = context.theta
        challenge, responses_m, response_t = proof
        theta = (
            kappa,
            nu,
            sigma_prime,
            ((challenge + 1) % order, responses_m, response_t),
        )
    elif attack_id == "wrong_verification_key":
        _, wrong_keys = ttp_keygen(context.params, 2, 3)
        verification_key = agg_key(
            context.params, [wrong_keys[0], wrong_keys[1], None]
        )
        theta = context.theta
    else:
        _, _, g1, _, _, _ = context.params
        kappa, nu, sigma_prime, proof = context.theta
        h_prime, s_prime = sigma_prime
        theta = (kappa, nu, (h_prime + g1, s_prime), proof)

    accepted, behavior = _observe_verification(
        context, verification_key, theta
    )
    return {
        **metadata,
        "expected": "rejected",
        "observed": "accepted" if accepted else "rejected",
        "passed": not accepted,
        "implementation_behavior": behavior,
        "note": note,
        "scope": (
            "This experiment demonstrates this mutation's observed behavior; "
            "it is not a general security proof."
        ),
    }
