from pathlib import Path
import sys

# Allow direct execution as well as python -m demos.demo_...
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.actors import Organization, User
from src.credentials import issue_credential, transfer_credential
from src.group import DEMO_PARAMS, modexp
from src.pseudonym import authenticate_pseudonym, generate_pseudonym


def main() -> None:
    params = DEMO_PARAMS
    print(f"Toy group (INSECURE FOR REAL CRYPTOGRAPHY) {params}")

    alice = User.generate(params)
    print(f"\nAlice creates a master key with x = {alice.master_secret}, g^x = {alice.master_public}")

    issuer = Organization.generate(params)
    key = issuer.credential_key
    print(f"\nO creates a credential key with s1 = {key.s1}, s2 = {key.s2}")
    print(f"  h1 = {key.h1}, h2 = {key.h2}")

    print("\nAlice registers N_O with O")
    nym_O, _, _ = generate_pseudonym(alice, issuer, params, verbose=True)
    print("\nAlice authenticates N_O")
    authenticated = authenticate_pseudonym(alice, nym_O, params, verbose=True)
    print(f"  Authentication succeeded: {authenticated}")
    assert authenticated

    print("\nO issues a one-time credential")
    credential = issue_credential(issuer, nym_O, params, verbose=True)

    print("\nAlice registers a different pseudonym N_O2 with O2")
    receiver = Organization.generate(params)
    nym_O2, _, _ = generate_pseudonym(alice, receiver, params, verbose=True)
    while nym_O2 == nym_O:
        nym_O2, _, _ = generate_pseudonym(alice, receiver, params, verbose=True)
    print(f"  N_O = {nym_O}, N_O2 = {nym_O2}")
    print(f"  N_O != N_O2: {nym_O != nym_O2}")
    # Both nyms use the same hidden exponent. Computational unlinkability
    # is a security assumption and these toy parameters cannot demonstrate it.
    for nym in (nym_O, nym_O2):
        assert modexp(nym.a, alice.master_secret, params.p) == nym.b
    print("  Both pseudonyms satisfy b = a^x for Alice's x")

    print("\nAlice presents the credential to O2")
    result = transfer_credential(alice, credential, issuer.public_key, nym_O2, params, verbose=True)
    print(f"Credential accepted: {result.accepted}")
    assert result.accepted

    print("\nBob attempts to present Alice's credential with his own pseudonym")
    bob = User.generate(params)
    while bob.master_secret == alice.master_secret:
        bob = User.generate(params)
    nym_bob, _, _ = generate_pseudonym(bob, receiver, params)
    result = transfer_credential(bob, credential, issuer.public_key, nym_bob, params, verbose=True)
    print(f"Credential accepted: {result.accepted}")
    assert not result.accepted


if __name__ == "__main__":
    main()
