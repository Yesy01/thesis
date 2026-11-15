"""Streamlit walkthrough of the Section 4.3 one-time credential protocol."""

import streamlit as st

from src.actors import Organization, User
from src.attacks import tamper_credential, wrong_issuer_key
from src.campus import run_campus_demo
from src.chaum_pedersen import pi_equation_sides, pi_verify
from src.credentials import issue_credential, transfer_credential
from src.group import DEMO_PARAMS
from src.pseudonym import authenticate_pseudonym, generate_pseudonym

ISSUER, RECEIVER = "O", "O'"
USERS = ("Alice", "Bob")
ORGANIZATIONS = (ISSUER, RECEIVER)
state = st.session_state


def values(**items):
    st.code("\n".join(f"{label} = {value}" for label, value in items.items()), language=None)


def check(label, valid):
    if valid is None:
        st.info(f"{label} · SKIPPED")
    elif valid:
        st.success(f"{label} · PASS")
    else:
        st.error(f"{label} · FAIL")


def protocol_flow(organization, *messages):
    user, receiver = st.columns(2)
    user.markdown("**User**")
    receiver.markdown(f"**Organization {organization}**")
    for direction, message in messages:
        sender, recipient = st.columns(2)
        if direction == "→":
            sender.markdown(f"{message} →")
        elif direction == "←":
            recipient.markdown(f"← {message}")
        else:
            sender.markdown(f"↔ {message}")


def display_pi(proof):
    values(**{"Prover sends A": proof.A, "Prover sends B": proof.B,
              "Verifier sends c": proof.c, "Prover replies with y": proof.y})
    st.caption("In Protocol Π (§4.2), the prover answers c with y = r + c·x mod q.")


def invalidate_presentations():
    state.pop("transfer", None)
    state.pop("attack", None)


def replace_actor(collection, name, actor):
    state[collection][name] = actor
    affected = 0 if collection == "users" else 1
    for pair in tuple(state.registrations):
        if pair[affected] == name:
            del state.registrations[pair]
    if collection == "users":
        state.credentials.pop(name, None)
    elif name == ISSUER:
        state.credentials.clear()
    invalidate_presentations()


def setup_tab():
    st.caption("Paper §4.1 (Setting) and §4.3 (User Master Key Generation and Organization Credential Key Generation)")
    st.markdown("**1. Load the group**")
    if st.button("Generate Group Parameters"):
        state.params = DEMO_PARAMS
        for collection in ("users", "organizations", "registrations", "credentials"):
            state[collection].clear()
        invalidate_presentations()
    params = state.get("params")
    if params is None:
        st.info("Click Generate Group Parameters first.")
    else:
        values(p=params.p, q=params.q, g=params.g)
    st.caption("The button loads fixed values. It does not generate new primes.")
    with st.expander("How the group was built"):
        st.markdown(
            "The demo uses primes q = 1,000,000,007 and p = 44q + 1. "
            "The generator is g = 2^44 mod p. Since g^q mod p = 1 and g ≠ 1, "
            "g has order q. The tests check both primes by trial division."
        )

    st.markdown("**2. Generate the keys**")
    user_column, org_column = st.columns(2)
    with user_column:
        for name in USERS:
            if st.button(f"Generate {name} Master Key", disabled=params is None):
                replace_actor("users", name, User.generate(params))
            if user := state.users.get(name):
                values(**{"g^x": user.master_public})
                with st.expander(f"{name}'s master secret"):
                    values(x=user.master_secret)
        st.caption("Each user chooses a secret x, publishes g^x, and uses x with every organization.")

    with org_column:
        for name in ORGANIZATIONS:
            if st.button(f"Generate Organization {name} Keys", disabled=params is None):
                replace_actor("organizations", name, Organization.generate(params))
            if organization := state.organizations.get(name):
                key = organization.credential_key
                values(**{"h1 = g^s1": key.h1, "h2 = g^s2": key.h2})
                with st.expander(f"Organization {name} secrets"):
                    values(s1=key.s1, s2=key.s2)
        st.caption("O issues credentials. O′ receives them and verifies them with O’s public key.")


def pseudonym_tab():
    st.caption("Paper §4.3 (Pseudonym Generation). The paper also calls a pseudonym a nym.")
    left, right = st.columns(2)
    name = left.selectbox("User", USERS, key="nym_user")
    organization = right.selectbox("Organization", ORGANIZATIONS)
    protocol_flow(organization, ("→", "Send (ã, b̃)"), ("←", "Return a"), ("↔", "Run Π"))

    pair = (name, organization)
    ready = name in state.users and organization in state.organizations
    if st.button("Generate Pseudonym", disabled=not ready):
        try:
            state.registrations[pair] = generate_pseudonym(
                state.users[name], state.organizations[organization],
                state.params, capture_trace=True,
            )
        except ValueError as error:
            st.error(str(error))
        else:
            if organization == ISSUER:
                state.credentials.pop(name, None)
            invalidate_presentations()

    if not ready:
        st.info("Generate the selected user's and organization's keys in Setup.")
    if pair not in state.registrations:
        return

    nym, proof, trace = state.registrations[pair]
    st.markdown(f"**1. {name} sends (ã, b̃)**")
    st.caption("Choose γ to make a new base ã, then raise it to the secret x.")
    values(gamma=trace.gamma, **{"a_tilde = g^gamma": trace.a_tilde, "b_tilde = a_tilde^x": trace.b_tilde})
    st.markdown(f"**2. {organization} sends back a**")
    st.caption("The organization chooses r and raises ã to r.")
    values(r=trace.r, **{"a = a_tilde^r": nym.a})
    st.markdown(f"**3. {name} computes b**")
    st.caption("Raise the returned base a to the same secret x.")
    values(**{"b = a^x": nym.b})
    st.markdown("**4. Both parties run Π**")
    st.latex(r"\log_a b = \log_{\tilde a}\tilde b")
    st.caption("The two equations check that one secret x fits both pairs. All group values are reduced modulo p.")
    display_pi(proof)
    statement = (nym.a, nym.b, trace.a_tilde, trace.b_tilde, proof, state.params)
    first, second = pi_equation_sides(*statement)
    st.code(
        f"a^y == A * b^c                  {first[0]} == {first[1]}\n"
        f"a_tilde^y == B * b_tilde^c      {second[0]} == {second[1]}",
        language=None,
    )
    valid = pi_verify(*statement)
    check("Pseudonym registration Π", valid)
    if valid:
        st.caption(f"{name} and {organization} save (a, b).")


def display_gamma(label, statement, public_pair, second_pair, witness, transcript, trace):
    with st.expander(f"{label} · {statement}", expanded=True):
        st.caption(f"In Protocol Γ (§4.2), O proves it knows {witness}. "
                   f"In the formulas below, (g, h) means {public_pair} and "
                   f"(g_tilde, h_tilde) means {second_pair}.")
        st.markdown("**O sends the Π commitment**")
        values(A=trace.interactive.A, B=trace.interactive.B)
        st.caption("These A and B belong to the proof. The issuer’s A and B appear above.")
        st.markdown("**The user blinds the commitment and sends c**")
        values(alpha=trace.alpha, beta=trace.beta, gamma=trace.gamma)
        values(**{
            "A_prime = A * g^alpha * h^beta": transcript.A_prime,
            "B_prime = (B * g_tilde^alpha * h_tilde^beta)^gamma": transcript.B_prime,
        })
        values(**{"H(A_prime, B_prime)": transcript.c_hash, "c = (H + beta) mod q": trace.interactive.c})
        st.markdown("**O replies with y. The user checks it and saves the proof.**")
        values(y=trace.interactive.y, **{"y_prime = (y + alpha) mod q": transcript.y_prime})
        values(**{f"{label} = (A_prime, B_prime, H, y_prime)": (
            transcript.A_prime, transcript.B_prime, transcript.c_hash, transcript.y_prime,
        )})
        st.caption("The saved proof is a noninteractive Π proof (Π_NI). O′ can check it using the blinded values.")
        check("Blinded Π_NI verification", trace.blinded_valid)


def issuance_tab():
    st.caption("Paper §4.3 (Issuing a Credential)")
    protocol_flow(ISSUER, ("←", "Send A and B"), ("↔", "Run Γ for T1"), ("↔", "Run Γ for T2"))
    name = st.selectbox("Credential holder", USERS)
    registration = state.registrations.get((name, ISSUER))
    if st.button("Issue Credential", disabled=registration is None):
        nym = registration[0]
        if authenticate_pseudonym(state.users[name], nym, state.params):
            traces = []
            credential = issue_credential(
                state.organizations[ISSUER], nym, state.params, on_trace=traces.append,
            )
            state.credentials[name] = (credential, traces[0])
            invalidate_presentations()
        else:
            st.error("Issuer pseudonym authentication · FAIL")

    if registration is None:
        st.info(f"Generate a pseudonym for {name} with O before issuing a credential.")
    if name not in state.credentials:
        return

    credential, trace = state.credentials[name]
    nym = registration[0]
    st.markdown(f"**1. {name} authenticates with O**")
    values(**{"Registered (a, b)": (nym.a, nym.b)})
    st.caption("O checks that the user knows x for b = a^x by running Π with (a, b) on both sides.")
    check("Issuer pseudonym authentication", True)
    st.markdown("**2. O sends A and B**")
    st.caption("O uses s2 to compute A, then uses s1 to compute B from a and A.")
    values(**{"A = b^s2": trace.A, "B = (a*A)^s1": trace.B})
    st.markdown("**3. The user chooses γ and runs Γ twice with O**")
    st.caption("Use the same γ for both proofs so they refer to the same blinded credential.")
    values(gamma=trace.T1.gamma)
    display_gamma("T1", "log_b(A) = log_g(h2)", "(g, h2)", "(b, A)", "s2", credential.T1, trace.T1)
    display_gamma("T2", "log_(a*A)(B) = log_g(h1)", "(g, h1)", "(a*A, B)", "s1", credential.T2, trace.T2)
    st.markdown("**4. The user saves the one-time credential C_UO**")
    st.caption("Raise a, b, A, and B to γ and save both proofs alongside them.")
    values(**{
        "a^gamma": credential.a_prime, "b^gamma": credential.b_prime,
        "A^gamma": credential.A_prime, "B^gamma": credential.B_prime,
        "T1": credential.T1, "T2": credential.T2,
    })
    st.warning("Reusing this one-time credential can link presentations.")


def present(name, credential, key):
    nym = state.registrations[(name, RECEIVER)][0]
    proofs = []
    result = transfer_credential(
        state.users[name], credential, key, nym, state.params, on_ownership_proof=proofs.append,
    )
    return result, proofs[0] if proofs else None, nym, credential, key


def display_presentation(result, proof, nym, credential, key):
    with st.expander("Values used by O′"):
        values(**{
            "Registered (ã, b̃)": (nym.a, nym.b),
            "Credential (a′, b′, A′, B′)": (
                credential.a_prime, credential.b_prime, credential.A_prime, credential.B_prime,
            ),
            "Issuer key (g, h1, h2)": (state.params.g, key.h1, key.h2),
        })
    st.markdown("**1. O′ checks T1 as a noninteractive Π proof**")
    st.latex(r"\log_{b'} A' = \log_g h_2")
    st.caption("The same issuer secret s2 connects g to h2 and b′ to A′.")
    check("T1", result.transcript_1_valid)
    st.markdown("**2. O′ checks T2 the same way**")
    st.latex(r"\log_{a'A'} B' = \log_g h_1")
    st.caption("The same issuer secret s1 connects g to h1 and a′A′ to B′.")
    check("T2", result.transcript_2_valid)
    st.markdown("**3. The presenter proves ownership with Π**")
    st.latex(r"\log_{\tilde a}\tilde b = \log_{a'} b'")
    st.caption("The same x must link the registered pair (ã, b̃) and the credential pair (a′, b′).")
    check("Ownership Π", result.ownership_proof_valid if proof is not None else None)
    if proof is not None:
        with st.expander("Ownership Π transcript"):
            display_pi(proof)
    else:
        st.caption("O′ checks ownership only after the credential passes verification.")
    if result.accepted:
        st.success("## CREDENTIAL ACCEPTED")
    else:
        st.error("## CREDENTIAL REJECTED")


def transfer_tab():
    st.caption("Paper §4.3 (Transferring a Credential to Another Organization)")
    protocol_flow(RECEIVER, ("→", "Send credential"), ("↔", "Run ownership Π"), ("←", "Accept or reject"))
    ready = "Alice" in state.credentials and ("Alice", RECEIVER) in state.registrations
    if st.button("Transfer Alice's Credential", disabled=not ready):
        state.transfer = present("Alice", state.credentials["Alice"][0], state.organizations[ISSUER].public_key)
    if "Alice" not in state.credentials:
        st.info("In Credential Issuance, issue Alice a credential from O.")
    if ("Alice", RECEIVER) not in state.registrations:
        st.info("In Pseudonym Generation, register Alice with O′.")
    if "transfer" in state:
        display_presentation(*state.transfer)


ATTACKS = (
    ("Use Bob's pseudonym with Alice's credential", None,
     "Both issuer proofs still pass. Bob’s secret fits his own pseudonym, but the credential pair uses Alice’s secret."),
    ("Modify A", "A_prime",
     "Changing A′ changes what T1 proves and changes the base a′A′ in T2."),
    ("Modify B", "B_prime",
     "T2 checks B′. Changing B′ breaks that check."),
    ("Modify T1 response", "T1",
     "T1 still has its original commitment and challenge, so the edited response fails verification."),
    ("Modify T2 response", "T2",
     "T2 still has its original commitment and challenge, so the edited response fails verification."),
    ("Use wrong issuer public key", "key",
     "T1 checks the new h2 against a proof made for the original h2. T2 still uses the original h1."),
)


def attack_tab():
    st.caption("Try changing an input to the transfer checks from §4.3.")
    issued = "Alice" in state.credentials
    if not issued:
        st.info("Issue a credential to Alice to enable attacks.")
    st.caption("Register Alice with O′ for the tampering attacks and Bob with O′ for the impersonation attempt.")
    for label, field, reason in ATTACKS:
        presenter = "Bob" if field is None else "Alice"
        ready = issued and (presenter, RECEIVER) in state.registrations
        if st.button(label, disabled=not ready):
            credential = state.credentials["Alice"][0]
            key = state.organizations[ISSUER].public_key
            if field == "key":
                key = wrong_issuer_key(key, state.params)
            elif field is not None:
                credential = tamper_credential(credential, field, state.params)
            state.attack = (label, reason, present(presenter, credential, key))

    if "attack" in state:
        label, reason, presentation = state.attack
        st.subheader(label)
        st.markdown(reason)
        display_presentation(*presentation)


def campus_checks(result):
    t1, t2, ownership = st.columns(3)
    with t1:
        check("T1", result.transcript_1_valid)
    with t2:
        check("T2", result.transcript_2_valid)
    with ownership:
        check("Ownership Π", result.ownership_proof_valid)


def campus_tab():
    st.subheader("Alice’s campus pass")
    st.caption("Paper §4.3. The Registrar is the CA, the Student Office is O, and the Library is O′.")
    st.write(
        "Alice is enrolled. Bob is a visitor. The Registrar certifies enrollment, "
        "the Student Office issues passes, and the Library checks them."
    )
    if st.button("Run Campus Demo"):
        state.campus = run_campus_demo()
    if "campus" not in state:
        return
    demo = state.campus

    st.markdown("**1. Alice registers with the Registrar (CA)**")
    st.write("The Registrar records Alice’s name and master public key. The CA receives (g, g^x).")
    values(**{"g": demo.ca_registration.a_tilde, "g^x": demo.ca_registration.b_tilde})

    st.write("The Registrar sends back a = g^r. Alice computes b = a^x, and they run Π to register (a, b).")
    values(**{"Registrar sends a": demo.ca_pseudonym.a, "Alice computes b": demo.ca_pseudonym.b})

    st.markdown("**The Registrar issues Alice an enrollment credential**")
    st.write(
        "The Registrar sends A and B using its own issuer keys. Alice and the Registrar run Γ twice. "
        "Alice saves the blinded tuple below, including the two proofs, and presents it to the Student Office."
    )
    with st.expander("What Alice receives and saves"):
        trace = demo.enrollment_issuance
        enrollment = demo.enrollment_credential
        values(**{"Registrar sends A = b^s2": trace.A, "Registrar sends B = (a*A)^s1": trace.B})
        st.markdown("**Alice saves the enrollment credential**")
        values(a_prime=enrollment.a_prime, b_prime=enrollment.b_prime,
               A_prime=enrollment.A_prime, B_prime=enrollment.B_prime, T1=enrollment.T1, T2=enrollment.T2)
    with st.expander("Why Γ uses a hash"):
        st.write(
            "In interactive Π, the verifier sends a fresh challenge after seeing the commitment. "
            "The Student Office is absent when Alice gets the credential, so it cannot send that challenge. "
            "Instead, Γ uses H(A′, B′) to make a proof the Office can check later. "
            "The Office recomputes the challenge from the saved commitment. "
            "The paper models H as a random oracle. The demo uses SHA-256 reduced modulo q."
        )

    st.markdown("**2. Alice registers with the Student Office (O)**")
    st.write(
        "The Office receives the randomized pair (ã, b̃). Alice presents the Registrar’s "
        "enrollment credential. The Office checks both issuer proofs and confirms Alice owns it."
    )
    values(**{"ã": demo.office_registration.a_tilde, "b̃": demo.office_registration.b_tilde})
    campus_checks(demo.enrollment_check)

    st.markdown("**3. Alice gets a pass and presents it at the Library (O′)**")
    st.write("The Office issues the pass using Γ twice. The Library checks T1, T2, and ownership against Alice’s library pseudonym.")
    campus_checks(demo.library_access)
    check("Alice’s library access", demo.library_access.accepted)

    st.markdown("**4. Bob copies Alice’s pass**")
    st.write("The copied pass has valid issuer proofs. Bob’s library pseudonym uses a different secret, so ownership fails.")
    campus_checks(demo.stolen_pass)
    check("Bob’s library access with a copied pass", demo.stolen_pass.accepted)

    st.markdown("**5. The Registrar and Bob collude**")
    st.write(
        "The Registrar gives Bob a valid enrollment credential even though he is a visitor. "
        "The Office trusts the Registrar and issues Bob a pass. The Library’s checks all pass."
    )
    check("Bob’s enrollment credential at the Office", demo.false_ca_attestation.accepted)
    campus_checks(demo.access_after_false_attestation)
    check("Bob’s library access with a false enrollment claim", demo.access_after_false_attestation.accepted)

    st.markdown("**6. The Student Office and Bob collude**")
    st.write(
        "In a separate case, the Office skips the enrollment requirement and issues Bob a pass "
        "under its trusted key. The Library can check who issued the pass and who owns it."
    )
    campus_checks(demo.unauthorized_issuance)
    check("Bob’s library access with a pass from a dishonest issuer", demo.unauthorized_issuance.accepted)

    st.markdown("**7. The Registrar and Student Office share campus records**")
    st.write(
        "Suppose the Office also asks for a campus ID when Alice registers. "
        "The Registrar and Office can then match the ID in their records and attach Alice’s name "
        "to her Office pseudonym. The campus ID is extra information outside the protocol."
    )
    with st.expander("Records with an extra campus ID"):
        nym = demo.office_pseudonym
        st.code(f"Registrar | CAMPUS-042 | Alice\nStudent Office | CAMPUS-042 | ({nym.a}, {nym.b})", language=None)

    st.markdown("**8. The Library and Print Lab compare passes**")
    st.write(
        "Alice presents the same pass to the Print Lab with a fresh ownership proof. "
        "Both services can link the visits by comparing the pass tuple. "
        "To attach Alice’s name, they would need a link to an identified record, such as a campus login."
    )
    check("Alice’s print lab access", demo.print_lab_access.accepted)
    with st.expander("Pass tuple seen by both services"):
        p = demo.student_pass
        values(a_prime=p.a_prime, b_prime=p.b_prime, A_prime=p.A_prime, B_prime=p.B_prime, T1=p.T1, T2=p.T2)


def main():
    st.set_page_config(page_title="LRSW99 Pseudonym System", layout="wide")
    st.title("LRSW99 Pseudonym System")
    st.caption("Follow Sections 4.1 to 4.3 of Pseudonym Systems by Lysyanskaya, Rivest, Sahai, and Wolf.")
    st.warning("These parameters are insecure.")
    with st.expander("How to run the demo"):
        st.markdown(
            "1. In **Setup**, load the group and generate keys for Alice, O, and O′.\n"
            "2. In **Pseudonym Generation**, register Alice with O and then with O′.\n"
            "3. In **Credential Issuance**, issue Alice a credential from O.\n"
            "4. In **Credential Transfer**, present Alice’s credential to O′.\n"
            "5. In **Attack Demo**, try editing the credential. To try impersonation, "
            "generate Bob’s key and register him with O′ first."
        )

    for collection in ("users", "organizations", "registrations", "credentials"):
        state.setdefault(collection, {})
    tabs = st.tabs([
        "Setup", "Pseudonym Generation", "Credential Issuance", "Credential Transfer", "Attack Demo", "Campus Demo",
    ])
    screens = (setup_tab, pseudonym_tab, issuance_tab, transfer_tab, attack_tab, campus_tab)
    for tab, render in zip(tabs, screens):
        with tab:
            render()


if __name__ == "__main__":
    main()
