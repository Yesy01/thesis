#!/usr/bin/env python3
"""Minimal in-memory Ashoka complaint simulation using original Coconut."""

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


def main():
    authority_count = 3
    threshold = 2
    issue_id = 20261007
    complaint = {
        "id": "complaint-001",
        "text": "The hostel water supply has been unavailable since morning.",
    }
    used_list = set()

    params = setup(2)
    _, order, _, _, _, _ = params
    student_secret_k = order.random()
    private_attributes = [student_secret_k]
    public_attributes = [issue_id]

    secret_keys, verification_keys = ttp_keygen(
        params, threshold, authority_count
    )
    aggregate_vk = agg_key(
        params, [verification_keys[0], verification_keys[1], None]
    )

    elgamal_private, gamma = elgamal_keygen(params)
    request = prepare_blind_sign(
        params,
        gamma,
        private_attributes,
        public_m=public_attributes,
    )
    blinded_shares = [
        blind_sign(
            params,
            secret_keys[i],
            gamma,
            request,
            public_m=public_attributes,
        )
        for i in range(threshold)
    ]
    shares = [
        unblind(params, blinded_share, elgamal_private)
        for blinded_share in blinded_shares
    ]
    credential = agg_cred(params, [shares[0], shares[1], None])

    randomized_showing = prove_cred(
        params, aggregate_vk, credential, private_attributes
    )
    accepted = verify_cred(
        params,
        aggregate_vk,
        randomized_showing,
        public_m=public_attributes,
    )
    assert accepted

    # TODO: application-specific construction requiring ZK binding to
    # credential secret k. This local identifier is only a simulation and is
    # not a Coconut-bound nullifier or an anonymous double-use prevention
    # mechanism.
    local_record = (issue_id, complaint["id"])
    if local_record in used_list:
        raise RuntimeError("complaint already recorded in this process")
    used_list.add(local_record)

    print("Ashoka Coconut complaint simulation")
    print("authorities = {}".format(authority_count))
    print("threshold = {}".format(threshold))
    print("IssueID = {}".format(issue_id))
    print("credential randomized = True")
    print("credential accepted = {}".format(accepted))
    print("complaint recorded in local UsedList = True")
    print("UsedList provides no cryptographic nullifier binding")


if __name__ == "__main__":
    main()
