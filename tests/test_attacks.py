"""Contract tests for the adversarial MediShield demo scenarios."""

import pytest

from demo.attacks import (
    changed_destination,
    expired_approval,
    prompt_injection_note,
    replay_consumed_approval,
    revoked_approval,
    substitute_patient,
    tamper_dose,
    unauthorized_actor,
    valid_action,
)


@pytest.mark.parametrize(
    ("scenario", "expected_rule"),
    [
        (tamper_dose, "intent hash mismatch"),
        (substitute_patient, "intent hash mismatch"),
        (unauthorized_actor, "role not permitted"),
        (replay_consumed_approval, "approval already consumed"),
        (changed_destination, "destination not pinned"),
        (expired_approval, "approval expired"),
        (revoked_approval, "approval revoked"),
    ],
)
def test_attack_is_blocked_without_changing_backend(scenario, expected_rule):
    """Each blocked scenario must leave the simulated backend unchanged."""

    result = scenario()

    assert result["decision"] == "blocked"
    assert result["rule"] == expected_rule
    assert result["state_changed"] is False
    assert result["backend_state_before"] == result["backend_state_after"]


def test_prompt_injection_note_has_no_effect_on_a_valid_decision():
    """A note must not be treated as a tool instruction or protected action."""

    injected_result = prompt_injection_note()
    control_result = valid_action()

    assert injected_result["decision"] == "allowed"
    assert injected_result["decision"] == control_result["decision"]
    assert injected_result["rule"] == control_result["rule"]
    assert injected_result["changed_fields"] == control_result["changed_fields"]
    assert injected_result["state_changed"] == control_result["state_changed"]


def test_valid_action_is_allowed():
    """The guard must permit the exact action a clinician approved."""

    result = valid_action()

    assert result["decision"] == "allowed"
