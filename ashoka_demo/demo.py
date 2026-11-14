#!/usr/bin/env python3
"""Minimal in-memory Ashoka complaint simulation using original Coconut."""

from ashoka_demo.protocol import InMemoryUsedList, execute_flow


def main():
    issue_id = 20261007
    complaint = {
        "id": "complaint-001",
        "text": "The hostel water supply has been unavailable since morning.",
    }
    result = execute_flow(
        issue_id,
        complaint["id"],
        complaint["text"],
        InMemoryUsedList(),
    )

    print("Ashoka Coconut complaint simulation")
    print("authorities = {}".format(result["authority_count"]))
    print("threshold = {}".format(result["threshold"]))
    print("IssueID = {}".format(issue_id))
    print("credential randomized = {}".format(result["credential_randomized"]))
    print("credential accepted = {}".format(result["accepted"]))
    print("complaint recorded in local UsedList = {}".format(result["recorded"]))
    print("UsedList provides no cryptographic nullifier binding")


if __name__ == "__main__":
    main()
