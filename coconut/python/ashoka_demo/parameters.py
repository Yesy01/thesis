"""Public parameter descriptions for the educational interfaces."""

from hashlib import sha256

from coconut.scheme import setup


def _export_description(element):
    encoded = element.export()
    return {
        "bytes": len(encoded),
        "sha256": sha256(encoded).hexdigest()[:16],
    }


def describe_parameters(runtime):
    """Return public setup information without serializing secret material."""
    group, order, g1, hs, g2, _ = setup(2)
    order_value = int(order)
    return {
        "runtime": runtime,
        "group_implementation": "{}.{}".format(
            type(group).__module__, type(group).__name__
        ),
        "group_order": str(order_value),
        "group_order_bits": order_value.bit_length(),
        "pairing_groups": ["G1", "G2", "GT"],
        "g1": _export_description(g1),
        "g2": _export_description(g2),
        "attribute_generators": [
            _export_description(generator) for generator in hs
        ],
        "maximum_attributes": len(hs),
        "authority_count": 3,
        "threshold": 2,
        "selected_authorities": [1, 2],
        "private_attributes": ["student secret k"],
        "public_attributes": ["IssueID"],
        "hash_to_group": "H(cm) via BpGroup.hashG1",
        "issuance_proof": "Fiat-Shamir proof pi_s",
        "showing_proof": "Fiat-Shamir proof pi_v",
        "verification_equation": "e(h', kappa + public terms) = e(s' + nu, g2)",
    }
