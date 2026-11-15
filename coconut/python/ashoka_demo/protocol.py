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

STAGE_DEFINITIONS = (
    {
        "algorithm": "Setup",
        "function": "setup(2)",
        "file": "coconut/scheme.py",
        "actor": "System",
        "activity": "Initializing the pairing group and deriving two attribute generators.",
    },
    {
        "algorithm": "TTPKeyGen + AggKey",
        "function": "ttp_keygen(); agg_key()",
        "file": "coconut/scheme.py",
        "actor": "Authority setup",
        "activity": "Generating three key shares and combining the selected verification shares.",
    },
    {
        "algorithm": "PrepareBlindSign",
        "function": "elgamal_keygen(); prepare_blind_sign()",
        "file": "coconut/utils.py + coconut/scheme.py",
        "actor": "User",
        "activity": "Committing to the attributes, encrypting private k, and constructing the issuance proof.",
    },
    {
        "algorithm": "BlindSign",
        "function": "blind_sign() × 2",
        "file": "coconut/scheme.py",
        "actor": "Authorities A1 + A2",
        "activity": "Checking the issuance proof and producing two blinded credential shares.",
    },
    {
        "algorithm": "Unblind",
        "function": "unblind() × 2",
        "file": "coconut/scheme.py",
        "actor": "User",
        "activity": "Removing ElGamal blinding from both partial credentials.",
    },
    {
        "algorithm": "AggCred",
        "function": "agg_cred()",
        "file": "coconut/scheme.py",
        "actor": "User",
        "activity": "Interpolating the two ordered shares into one threshold credential.",
    },
    {
        "algorithm": "ProveCred",
        "function": "prove_cred()",
        "file": "coconut/scheme.py",
        "actor": "Credential holder",
        "activity": "Randomizing the credential and constructing the showing proof.",
    },
    {
        "algorithm": "VerifyCred",
        "function": "verify_cred()",
        "file": "coconut/scheme.py",
        "actor": "Verifier",
        "activity": "Checking the showing proof and the final pairing equation.",
    },
    {
        "algorithm": "Application record",
        "function": "InMemoryUsedList.record()",
        "file": "ashoka_demo/protocol.py",
        "actor": "Application",
        "activity": "Checking the process-local UsedList before recording the complaint.",
    },
)


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


def _emit(event_callback, event):
    if event_callback is not None:
        event_callback(event)


def _begin_stage(stage_number, event_callback):
    definition = STAGE_DEFINITIONS[stage_number - 1]
    _emit(
        event_callback,
        {
            "type": "stage_start",
            "stage": {
                "number": stage_number,
                "status": "running",
                **definition,
            },
        },
    )
    return perf_counter()


def _finish_stage(stages, stage_number, started, detail, event_callback):
    stage = {
        "number": stage_number,
        "status": "complete",
        "duration_ms": round((perf_counter() - started) * 1000, 2),
        "detail": detail,
        **STAGE_DEFINITIONS[stage_number - 1],
    }
    stages.append(stage)
    _emit(event_callback, {"type": "stage_complete", "stage": stage})


def execute_flow(
    issue_id,
    complaint_id,
    complaint_text,
    used_list=None,
    event_callback=None,
):
    """Execute one real 2-of-3 Coconut issuance and showing flow.

    The complaint content and identifier are application data. The Coconut
    credential contains a random private student secret and the public IssueID.
    """
    _validate_inputs(issue_id, complaint_id, complaint_text)
    if used_list is None:
        used_list = InMemoryUsedList()

    stages = []
    flow_started = perf_counter()

    started = _begin_stage(1, event_callback)
    params = setup(2)
    _, order, _, _, _, _ = params
    student_secret_k = order.random()
    private_attributes = [student_secret_k]
    public_attributes = [issue_id]
    _finish_stage(
        stages,
        1,
        started,
        "Initialized the pairing group and two attribute generators.",
        event_callback,
    )

    started = _begin_stage(2, event_callback)
    secret_keys, verification_keys = ttp_keygen(
        params, THRESHOLD, AUTHORITY_COUNT
    )
    selected_verification_keys = [
        verification_keys[0],
        verification_keys[1],
        None,
    ]
    aggregate_vk = agg_key(params, selected_verification_keys)
    _finish_stage(
        stages,
        2,
        started,
        "Generated three authority shares and aggregated authorities 1 and 2.",
        event_callback,
    )

    started = _begin_stage(3, event_callback)
    elgamal_private, gamma = elgamal_keygen(params)
    request = prepare_blind_sign(
        params,
        gamma,
        private_attributes,
        public_m=public_attributes,
    )
    _finish_stage(
        stages,
        3,
        started,
        "Committed to private k and public IssueID, encrypted k, and created the issuance proof.",
        event_callback,
    )

    started = _begin_stage(4, event_callback)
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
    _finish_stage(
        stages,
        4,
        started,
        "Authorities 1 and 2 verified the issuance proof and returned blinded shares.",
        event_callback,
    )

    started = _begin_stage(5, event_callback)
    shares = [
        unblind(params, blinded_share, elgamal_private)
        for blinded_share in blinded_shares
    ]
    _finish_stage(
        stages,
        5,
        started,
        "Removed the user's ElGamal blinding from both partial credentials.",
        event_callback,
    )

    started = _begin_stage(6, event_callback)
    credential = agg_cred(params, [shares[0], shares[1], None])
    _finish_stage(
        stages,
        6,
        started,
        "Aggregated two ordered shares with the original Lagrange interpolation helper.",
        event_callback,
    )

    started = _begin_stage(7, event_callback)
    randomized_showing = prove_cred(
        params, aggregate_vk, credential, private_attributes
    )
    credential_randomized = randomized_showing[2] != credential
    _finish_stage(
        stages,
        7,
        started,
        "Randomized the credential and generated the showing proof without revealing k.",
        event_callback,
    )

    started = _begin_stage(8, event_callback)
    accepted = verify_cred(
        params,
        aggregate_vk,
        randomized_showing,
        public_m=public_attributes,
    )
    if not accepted:
        raise RuntimeError("the original Coconut verifier rejected the showing")
    _finish_stage(
        stages,
        8,
        started,
        "Verified the showing proof and final pairing equation for the public IssueID.",
        event_callback,
    )

    started = _begin_stage(9, event_callback)
    recorded = used_list.record(issue_id, complaint_id)
    _finish_stage(
        stages,
        9,
        started,
        (
            "Stored the local complaint record."
            if recorded
            else "Rejected a duplicate local complaint record."
        ),
        event_callback,
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
