"""Contract tests for the adversarial MediShield demo scenarios."""

import pytest

from demo.attacks import (
    changed_destination,
    expired_approval,
    guard_off_vs_guard_on,
    prompt_injection_note,
    replay_consumed_approval,
    revoked_approval,
    substitute_patient,
    tamper_dose,
    tool_registry_tampering,
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


def test_guard_off_comparison_uses_real_backend_and_gateway():
    result = guard_off_vs_guard_on()

    assert result["guard_off"]["decision"] == "bypassed"
    assert result["guard_off"]["state_changed"] is True
    assert result["guard_off"]["backend_state_before"] != result["guard_off"]["backend_state_after"]

    assert result["guard_on"]["decision"] == "blocked"
    assert result["guard_on"]["rule"] == "intent hash mismatch"
    assert result["guard_on"]["state_changed"] is False
    assert result["guard_on"]["backend_state_before"] == result["guard_on"]["backend_state_after"]


def test_tool_registry_tampering_is_detected_and_restored():
    result = tool_registry_tampering()

    assert result["simulated_registry"]["status"] == "drift"
    assert "unexpected tool: unexpected_tool" in result["simulated_registry"]["differences"]
    assert result["blocked"]["decision"] == "blocked"
    assert result["blocked"]["rule"] == "tool registry drift"
    assert result["blocked"]["state_changed"] is False
    assert result["blocked"]["approval_consumed"] is False
    assert result["blocked"]["handler_invoked"] is False
    assert result["blocked"]["handler_calls"] == 0
    assert result["blocked"]["evidence"] is not None
    assert result["blocked"]["evidence"]["failed_check"] == "tool registry drift"
    assert result["blocked"]["evidence"]["is_simulation"] is True
    assert result["blocked"]["backend_state_before"] == result["blocked"]["backend_state_after"]
    assert result["expected_fingerprint_before"] == result["expected_fingerprint_after"]
    assert result["restored"]["registry"]["status"] == "trusted"
    assert result["restored"]["decision"] == "allowed"
    assert result["restored"]["state_changed"] is True
    assert result["restored"]["approval_consumed"] is True
