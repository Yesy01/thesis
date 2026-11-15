"""Tests for the educational application layer around Coconut."""

import pytest

from ashoka_demo.attacks import ATTACKS, run_attack
from ashoka_demo.parameters import describe_parameters
from ashoka_demo.protocol import InMemoryUsedList, execute_flow


def test_complete_application_flow_exposes_protocol_stages():
    used_list = InMemoryUsedList()
    events = []
    result = execute_flow(
        20261007,
        "complaint-test-001",
        "A locally executed educational complaint.",
        used_list,
        event_callback=events.append,
    )

    assert result["accepted"] is True
    assert result["recorded"] is True
    assert result["credential_randomized"] is True
    assert result["threshold"] == 2
    assert result["authority_count"] == 3
    assert [stage["algorithm"] for stage in result["stages"]] == [
        "Setup",
        "TTPKeyGen + AggKey",
        "PrepareBlindSign",
        "BlindSign",
        "Unblind",
        "AggCred",
        "ProveCred",
        "VerifyCred",
        "Application record",
    ]
    assert result["credential_attributes"] == {
        "private": ["student secret k"],
        "public": ["IssueID"],
    }
    assert "complaint text" in result["application_only_fields"]
    assert [event["type"] for event in events] == [
        event_type
        for _ in range(9)
        for event_type in ("stage_start", "stage_complete")
    ]
    assert [
        event["stage"]["number"]
        for event in events
        if event["type"] == "stage_start"
    ] == list(range(1, 10))
    assert events[0]["stage"]["actor"] == "System"
    assert events[-1]["stage"]["actor"] == "Application"


def test_used_list_rejects_duplicate_local_record():
    used_list = InMemoryUsedList()

    assert used_list.record(10, "same-id") is True
    assert used_list.record(10, "same-id") is False
    assert len(used_list) == 1


@pytest.mark.parametrize(
    "issue_id, complaint_id, complaint_text, message",
    [
        (0, "complaint", "text", "IssueID"),
        (1, "", "text", "Complaint ID"),
        (1, "complaint", "", "Complaint text"),
    ],
)
def test_invalid_application_input_is_rejected(
    issue_id, complaint_id, complaint_text, message
):
    with pytest.raises(ValueError, match=message):
        execute_flow(issue_id, complaint_id, complaint_text)


@pytest.mark.parametrize("attack_id", [item["id"] for item in ATTACKS])
def test_controlled_attack_experiment_is_rejected(attack_id):
    result = run_attack(attack_id)

    assert result["expected"] == "rejected"
    assert result["observed"] == "rejected"
    assert result["passed"] is True


def test_parameter_description_contains_only_public_setup_data():
    parameters = describe_parameters("test runtime")

    assert parameters["threshold"] == 2
    assert parameters["authority_count"] == 3
    assert parameters["maximum_attributes"] == 2
    assert parameters["group_order_bits"] > 200
    assert parameters["private_attributes"] == ["student secret k"]
    assert "secret" not in parameters
