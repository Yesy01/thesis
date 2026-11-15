"""Campus policy examples built on the Section 4.3 protocols."""

from dataclasses import dataclass

from .actors import Organization, User
from .credentials import Credential, IssuanceTrace, TransferResult, issue_credential, transfer_credential
from .group import DEMO_PARAMS
from .pseudonym import Pseudonym, PseudonymTrace, generate_pseudonym


@dataclass(frozen=True)
class CampusResult:
    ca_registration: PseudonymTrace
    ca_pseudonym: Pseudonym
    enrollment_credential: Credential
    enrollment_issuance: IssuanceTrace
    office_registration: PseudonymTrace
    office_pseudonym: Pseudonym
    enrollment_check: TransferResult
    student_pass: Credential
    library_access: TransferResult
    stolen_pass: TransferResult
    false_ca_attestation: TransferResult
    access_after_false_attestation: TransferResult
    unauthorized_issuance: TransferResult
    print_lab_access: TransferResult


def run_campus_demo() -> CampusResult:
    params = DEMO_PARAMS
    alice, bob = User.generate(params), User.generate(params)
    while bob.master_secret == alice.master_secret:
        bob = User.generate(params)
    registrar = Organization.generate(params, is_ca=True)
    office = Organization.generate(params)
    library = Organization.generate(params)
    print_lab = Organization.generate(params)

    alice_ca, _, ca_registration = generate_pseudonym(alice, registrar, params, capture_trace=True)
    alice_office, _, office_registration = generate_pseudonym(alice, office, params, capture_trace=True)
    alice_library, _, _ = generate_pseudonym(alice, library, params)
    alice_print_lab, _, _ = generate_pseudonym(alice, print_lab, params)
    bob_library, _, _ = generate_pseudonym(bob, library, params)

    # The campus policy treats a Registrar credential as evidence of enrollment.
    enrollment_traces: list[IssuanceTrace] = []
    enrollment = issue_credential(registrar, alice_ca, params, on_trace=enrollment_traces.append)
    enrollment_check = transfer_credential(alice, enrollment, registrar.public_key, alice_office, params)
    if not enrollment_check.accepted:
        raise ValueError("The Office rejected Alice’s enrollment credential.")
    student_pass = issue_credential(office, alice_office, params)
    library_access = transfer_credential(alice, student_pass, office.public_key, alice_library, params)
    stolen_pass = transfer_credential(bob, student_pass, office.public_key, bob_library, params)
    print_lab_access = transfer_credential(alice, student_pass, office.public_key, alice_print_lab, params)

    # A CA colluding with Bob certifies him despite his ineligibility.
    bob_ca, _, _ = generate_pseudonym(bob, registrar, params)
    bob_office, _, _ = generate_pseudonym(bob, office, params)
    false_enrollment = issue_credential(registrar, bob_ca, params)
    false_ca_attestation = transfer_credential(
        bob, false_enrollment, registrar.public_key, bob_office, params,
    )
    if not false_ca_attestation.accepted:
        raise ValueError("The Office rejected Bob’s Registrar credential.")
    pass_after_false_attestation = issue_credential(office, bob_office, params)
    access_after_false_attestation = transfer_credential(
        bob, pass_after_false_attestation, office.public_key, bob_library, params,
    )

    # In a separate scenario, the Office colludes with Bob and skips enrollment.
    unauthorized_pass = issue_credential(office, bob_office, params)
    unauthorized_issuance = transfer_credential(
        bob, unauthorized_pass, office.public_key, bob_library, params,
    )
    return CampusResult(
        ca_registration, alice_ca, enrollment, enrollment_traces[0],
        office_registration, alice_office, enrollment_check, student_pass,
        library_access, stolen_pass, false_ca_attestation, access_after_false_attestation,
        unauthorized_issuance, print_lab_access,
    )
