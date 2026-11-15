from pathlib import Path
from random import Random
from types import SimpleNamespace

from streamlit.testing.v1 import AppTest

from src.group import DEMO_PARAMS


def test_streamlit_walkthrough(monkeypatch):
    monkeypatch.setattr("src.group.secrets", SimpleNamespace(randbelow=Random(0).randrange))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run()

    def button(label):
        return next(item for item in app.button if item.label == label)

    def click(label):
        control = button(label)
        assert not control.disabled, label
        control.click().run()
        assert not app.exception, app.exception

    def select(label, value):
        control = next(item for item in app.selectbox if item.label == label)
        control.select(value).run()
        assert not app.exception, app.exception

    assert not app.exception
    assert len(app.tabs) == 6
    assert button("Generate Alice Master Key").disabled
    assert button("Issue Credential").disabled
    assert button("Transfer Alice's Credential").disabled

    click("Generate Group Parameters")
    click("Generate Alice Master Key")
    click("Generate Bob Master Key")
    click("Generate Organization O Keys")
    click("Generate Organization O' Keys")
    click("Generate Pseudonym")
    assert any("Pseudonym registration Π · PASS" == item.value for item in app.success)
    click("Issue Credential")
    assert sum(item.value == "Blinded Π_NI verification · PASS" for item in app.success) == 2
    credential, trace = app.session_state.credentials["Alice"]
    assert trace.T1.gamma == trace.T2.gamma

    select("Organization", "O'")
    click("Generate Pseudonym")
    select("User", "Bob")
    click("Generate Pseudonym")
    click("Transfer Alice's Credential")
    assert app.session_state.transfer[0].accepted
    transfer_tab = app.tabs[3]
    assert any("Transferring a Credential to Another Organization" in item.value for item in transfer_tab.caption)
    assert len(transfer_tab.get("latex")) == 3
    assert any("CREDENTIAL ACCEPTED" in item.value for item in app.success)

    expected_checks = {
        "Use Bob's pseudonym with Alice's credential": (True, True, False),
        "Modify A": (False, False, False),
        "Modify B": (True, False, False),
        "Modify T1 response": (False, True, False),
        "Modify T2 response": (True, False, False),
        "Use wrong issuer public key": (False, True, False),
    }
    for label, expected in expected_checks.items():
        click(label)
        _, _, (result, proof, *_) = app.session_state.attack
        assert (result.transcript_1_valid, result.transcript_2_valid, result.ownership_proof_valid) == expected
        assert (proof is not None) == all(expected[:2])
        assert any("CREDENTIAL REJECTED" in item.value for item in app.error)
        assert app.session_state.credentials["Alice"][0] == credential

    click("Generate Alice Master Key")
    assert button("Issue Credential").disabled
    assert button("Transfer Alice's Credential").disabled
    assert "Alice" not in app.session_state.credentials
    assert "transfer" not in app.session_state
    assert "attack" not in app.session_state


def test_campus_demo(monkeypatch):
    monkeypatch.setattr("src.group.secrets", SimpleNamespace(randbelow=Random(1).randrange))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run()
    campus = app.tabs[5]
    assert campus.label == "Campus Demo"
    campus.button[0].click().run()
    assert not app.exception, app.exception

    demo = app.session_state.campus
    assert demo.ca_registration.a_tilde == DEMO_PARAMS.g
    assert demo.ca_registration.b_tilde == pow(
        demo.office_registration.b_tilde, pow(demo.office_registration.gamma, -1, DEMO_PARAMS.q), DEMO_PARAMS.p,
    )
    assert any("What Alice receives and saves" == item.label for item in app.tabs[5].expander)
    assert any(f"Registrar sends a = {demo.ca_pseudonym.a}" in item.value for item in app.tabs[5].code)
    assert any(f"T1 = {demo.enrollment_credential.T1}" in item.value for item in app.tabs[5].code)
    assert demo.enrollment_check.accepted and demo.library_access.accepted
    assert demo.stolen_pass.transcript_1_valid and demo.stolen_pass.transcript_2_valid
    assert not demo.stolen_pass.ownership_proof_valid
    assert demo.false_ca_attestation.accepted and demo.access_after_false_attestation.accepted
    assert demo.unauthorized_issuance.accepted and demo.print_lab_access.accepted
