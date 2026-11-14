"""Reusable educational flow built on the unmodified Coconut library."""

from threading import Lock
from time import perf_counter

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


AUTHORITY_COUNT = 3
THRESHOLD = 2


class InMemoryUsedList:
    """Process-local complaint records; this is not a cryptographic nullifier."""

    def __init__(self):
        self._records = set()
        self._lock = Lock()

    def record(self, issue_id, complaint_id):
        key = (issue_id, complaint_id)
        with self._lock:
            if key in self._records:
                return False
            self._records.add(key)
            return True

    def __len__(self):
        with self._lock:
            return len(self._records)


def _validate_inputs(issue_id, complaint_id, complaint_text):
    if isinstance(issue_id, bool) or not isinstance(issue_id, int):
        raise ValueError("IssueID must be an integer")
    if issue_id <= 0 or issue_id >= 2 ** 63:
        raise ValueError("IssueID must be between 1 and 2^63 - 1")
    if not isinstance(complaint_id, str) or not complaint_id.strip():
        raise ValueError("Complaint ID is required")
    if len(complaint_id) > 120:
        raise ValueError("Complaint ID must be 120 characters or fewer")
    if not isinstance(complaint_text, str) or not complaint_text.strip():
        raise ValueError("Complaint text is required")
    if len(complaint_text) > 5000:
        raise ValueError("Complaint text must be 5000 characters or fewer")


def _stage(stages, algorithm, function, file_name, started, detail):
    stages.append(
        {
            "number": len(stages) + 1,
            "algorithm": algorithm,
            "function": function,
            "file": file_name,
            "status": "complete",
            "duration_ms": round((perf_counter() - started) * 1000, 2),
            "detail": detail,
        }
    )


def execute_flow(issue_id, complaint_id, complaint_text, used_list=None):
    """Execute one real 2-of-3 Coconut issuance and showing flow.

    The complaint content and identifier are application data. The Coconut
    credential contains a random private student secret and the public IssueID.
    """
    _validate_inputs(issue_id, complaint_id, complaint_text)
    if used_list is None:
        used_list = InMemoryUsedList()

    stages = []
    flow_started = perf_counter()

    started = perf_counter()
    params = setup(2)
    _, order, _, _, _, _ = params
    student_secret_k = order.random()
    private_attributes = [student_secret_k]
    public_attributes = [issue_id]
    _stage(
        stages,
        "Setup",
        "setup(2)",
        "coconut/scheme.py",
        started,
        "Initialized the pairing group and two attribute generators.",
    )

    started = perf_counter()
    secret_keys, verification_keys = ttp_keygen(
        params, THRESHOLD, AUTHORITY_COUNT
    )
    selected_verification_keys = [
        verification_keys[0],
        verification_keys[1],
        None,
    ]
    aggregate_vk = agg_key(params, selected_verification_keys)
    _stage(
        stages,
        "TTPKeyGen + AggKey",
        "ttp_keygen(); agg_key()",
        "coconut/scheme.py",
        started,
        "Generated three authority shares and aggregated authorities 1 and 2.",
    )

    started = perf_counter()
    elgamal_private, gamma = elgamal_keygen(params)
    request = prepare_blind_sign(
        params,
        gamma,
        private_attributes,
        public_m=public_attributes,
    )
    _stage(
        stages,
        "PrepareBlindSign",
        "elgamal_keygen(); prepare_blind_sign()",
        "coconut/utils.py + coconut/scheme.py",
        started,
        "Committed to private k and public IssueID, encrypted k, and created the issuance proof.",
    )

    started = perf_counter()
    blinded_shares = [
        blind_sign(
            params,
            secret_keys[index],
            gamma,
            request,
            public_m=public_attributes,
        )
        for index in range(THRESHOLD)
    ]
    _stage(
        stages,
        "BlindSign",
        "blind_sign() × 2",
        "coconut/scheme.py",
        started,
        "Authorities 1 and 2 verified the issuance proof and returned blinded shares.",
    )

    started = perf_counter()
    shares = [
        unblind(params, blinded_share, elgamal_private)
        for blinded_share in blinded_shares
    ]
    _stage(
        stages,
        "Unblind",
        "unblind() × 2",
        "coconut/scheme.py",
        started,
        "Removed the user's ElGamal blinding from both partial credentials.",
    )

    started = perf_counter()
    credential = agg_cred(params, [shares[0], shares[1], None])
    _stage(
        stages,
        "AggCred",
        "agg_cred()",
        "coconut/scheme.py",
        started,
        "Aggregated two ordered shares with the original Lagrange interpolation helper.",
    )

    started = perf_counter()
    randomized_showing = prove_cred(
        params, aggregate_vk, credential, private_attributes
    )
    credential_randomized = randomized_showing[2] != credential
    _stage(
        stages,
        "ProveCred",
        "prove_cred()",
        "coconut/scheme.py",
        started,
        "Randomized the credential and generated the showing proof without revealing k.",
    )

    started = perf_counter()
    accepted = verify_cred(
        params,
        aggregate_vk,
        randomized_showing,
        public_m=public_attributes,
    )
    if not accepted:
        raise RuntimeError("the original Coconut verifier rejected the showing")
    _stage(
        stages,
        "VerifyCred",
        "verify_cred()",
        "coconut/scheme.py",
        started,
        "Verified the showing proof and final pairing equation for the public IssueID.",
    )

    started = perf_counter()
    recorded = used_list.record(issue_id, complaint_id)
    _stage(
        stages,
        "Application record",
        "InMemoryUsedList.record()",
        "ashoka_demo/protocol.py",
        started,
        (
            "Stored the local complaint record."
            if recorded
            else "Rejected a duplicate local complaint record."
        ),
    )

    return {
        "accepted": accepted,
        "recorded": recorded,
        "duplicate": not recorded,
        "credential_randomized": credential_randomized,
        "authority_count": AUTHORITY_COUNT,
        "threshold": THRESHOLD,
        "selected_authorities": [1, 2],
        "issue_id": issue_id,
        "complaint_id": complaint_id.strip(),
        "used_list_size": len(used_list),
        "total_duration_ms": round((perf_counter() - flow_started) * 1000, 2),
        "credential_attributes": {
            "private": ["student secret k"],
            "public": ["IssueID"],
        },
        "application_only_fields": ["complaint ID", "complaint text"],
        "stages": stages,
        "security_boundary": (
            "UsedList is process-local and is not a Coconut-bound nullifier or "
            "anonymous double-use prevention mechanism."
        ),
    }
