from src.actors import MasterKey, Organization, User
from src.chaum_pedersen import pi_verify
from src.group import DEMO_PARAMS as GROUP, modexp
from src.pseudonym import authenticate_pseudonym, generate_pseudonym


def test_pseudonym_registration_and_authentication(monkeypatch):
    user = User.generate(GROUP)
    issuer = Organization.generate(GROUP)
    receiver = Organization.generate(GROUP)
    scalars = iter((7, 11, 13, 17))
    monkeypatch.setattr("src.pseudonym.random_scalar", lambda q, *, nonzero: next(scalars))

    nym, proof, trace = generate_pseudonym(user, issuer, GROUP, verbose=True)
    other_nym, _, _ = generate_pseudonym(user, receiver, GROUP)

    assert nym != other_nym
    for registered in (nym, other_nym):
        assert registered.b == modexp(registered.a, user.master_secret, GROUP.p)
        assert authenticate_pseudonym(user, registered, GROUP)
    assert trace is not None
    assert trace.a_tilde != GROUP.g
    assert pi_verify(nym.a, nym.b, trace.a_tilde, trace.b_tilde, proof, GROUP)

    wrong_x = user.master_secret % (GROUP.q - 1) + 1
    wrong_user = User(MasterKey(wrong_x, modexp(GROUP.g, wrong_x, GROUP.p)))
    assert not authenticate_pseudonym(wrong_user, nym, GROUP)


def test_ca_receives_master_public_key():
    user = User.generate(GROUP)
    ca = Organization.generate(GROUP, is_ca=True)
    nym, proof, trace = generate_pseudonym(user, ca, GROUP, verbose=True)
    assert trace is not None
    assert (trace.a_tilde, trace.b_tilde) == (GROUP.g, user.master_public)
    assert pi_verify(nym.a, nym.b, GROUP.g, user.master_public, proof, GROUP)
