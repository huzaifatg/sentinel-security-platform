"""Unit tests for the pure scoring engine (no database, no HTTP)."""

import random

import pytest

from backend.risk import (
    BEHAVIOURAL_KEYS,
    CONTROL_KEYS,
    SIGNALS,
    BehaviouralEvidence,
    Provenance,
    Severity,
    SignalInput,
    SignalState,
    SignalValidationError,
    apply_overrides,
    classify_auth,
    classify_network,
    compare,
    evaluate,
    finding_severity,
    legacy_inputs,
    severity_for,
)

E, D, U, NA = SignalState.ENABLED, SignalState.DISABLED, SignalState.UNKNOWN, SignalState.NOT_APPLICABLE


def profile(**overrides: SignalState) -> dict[str, SignalInput]:
    """Fully secure baseline (all controls enabled, behaviour normal) with overrides."""
    states = {key: E for key in CONTROL_KEYS} | {key: SignalState.NORMAL for key in BEHAVIOURAL_KEYS}
    states.update(overrides)
    return {key: SignalInput(state) for key, state in states.items()}


def test_weights_sum_to_100() -> None:
    assert sum(signal.weight for signal in SIGNALS) == 100


def test_all_controls_enabled_scores_zero_risk() -> None:
    result = evaluate("a", profile())
    assert (result.risk_score, result.security_score, result.severity) == (0, 100, Severity.LOW)
    assert result.findings == [] and result.coverage == 100


def test_everything_bad_scores_full_risk() -> None:
    result = evaluate("a", profile(**{k: D for k in CONTROL_KEYS}, **{k: SignalState.HIGH for k in BEHAVIOURAL_KEYS}))
    assert (result.risk_score, result.security_score, result.severity) == (100, 0, Severity.CRITICAL)
    assert len(result.findings) == len(SIGNALS)


def test_multiple_disabled_controls_have_exact_contributions() -> None:
    result = evaluate("a", profile(mfa=D, firewall=D))
    assert result.risk_score == 32 and result.security_score == 68 and result.severity == Severity.MEDIUM
    by_rule = {f.rule: f for f in result.findings}
    assert set(by_rule) == {"mfa_disabled", "firewall_disabled"}
    assert by_rule["mfa_disabled"].contribution == 20.0 and by_rule["mfa_disabled"].severity == Severity.CRITICAL
    assert by_rule["firewall_disabled"].contribution == 12.0 and by_rule["firewall_disabled"].severity == Severity.HIGH
    assert [f.rule for f in result.findings] == ["mfa_disabled", "firewall_disabled"]  # ordered by contribution
    assert sum(f.contribution for f in result.findings) == result.risk_score


def test_missing_signals_are_unknown_not_secure() -> None:
    result = evaluate("a", {})
    assert result.risk_score == 50 and result.coverage == 0
    assert all(s.state == U and s.source == Provenance.DEFAULT for s in result.signals)
    assert all(f.category == "unverified" for f in result.findings)
    assert all(f.severity in (Severity.LOW, Severity.MEDIUM) for f in result.findings)
    assert evaluate("a", {}).risk_score > evaluate("a", profile()).risk_score


def test_not_applicable_is_excluded_and_renormalised() -> None:
    result = evaluate("a", profile(screen_lock=NA, firewall=D))
    assert result.applicable_weight == 94
    assert result.raw_risk == pytest.approx(1200 / 94, abs=0.01)
    assert result.risk_score == 13
    assert next(s for s in result.signals if s.key == "screen_lock").applicable is False
    assert "Excluded as not applicable: Automatic screen lock" in result.explanation


def test_behavioural_signals_cannot_be_not_applicable_and_states_are_validated() -> None:
    with pytest.raises(SignalValidationError):
        evaluate("a", {"auth_activity": SignalInput(NA)})
    with pytest.raises(SignalValidationError):
        evaluate("a", {"firewall": SignalInput(SignalState.HIGH)})
    with pytest.raises(SignalValidationError):
        evaluate("a", {"bogus": SignalInput(E)})


@pytest.mark.parametrize("score,expected", [(-5, "low"), (0, "low"), (24, "low"), (25, "medium"), (49, "medium"),
                                            (50, "high"), (74, "high"), (75, "critical"), (100, "critical"), (150, "critical")])
def test_severity_bands(score: int, expected: str) -> None:
    assert severity_for(score).value == expected


def test_finding_severity_floors_and_unknown_cap() -> None:
    assert finding_severity(20, D) == Severity.CRITICAL
    assert finding_severity(10, D) == Severity.HIGH
    assert finding_severity(9.9, D) == Severity.MEDIUM
    assert finding_severity(4.9, D) == Severity.LOW
    assert finding_severity(20, U) == Severity.MEDIUM


def _random_profile(rng: random.Random) -> dict[str, SignalInput]:
    inputs = {key: SignalInput(rng.choice([E, D, U, NA])) for key in CONTROL_KEYS}
    inputs.update({key: SignalInput(rng.choice(list(SignalState.__members__.values())[4:] + [U])) for key in BEHAVIOURAL_KEYS})
    return inputs


def test_monotonicity_bounds_and_determinism_over_random_profiles() -> None:
    rng = random.Random(2026)
    for _ in range(400):
        base = _random_profile(rng)
        result = evaluate("a", base)
        assert 0 <= result.risk_score <= 100 and result.security_score == 100 - result.risk_score
        assert result.severity == severity_for(result.risk_score)
        assert evaluate("a", dict(reversed(list(base.items())))).risk_score == result.risk_score
        for key in CONTROL_KEYS:
            if base[key].state == NA:
                continue
            enabled = evaluate("a", {**base, key: SignalInput(E)}).raw_risk
            unknown = evaluate("a", {**base, key: SignalInput(U)}).raw_risk
            disabled = evaluate("a", {**base, key: SignalInput(D)}).raw_risk
            assert enabled <= unknown <= disabled, key


def test_auth_classification_thresholds_and_no_double_counting() -> None:
    assert classify_auth(BehaviouralEvidence()).state == U
    assert classify_auth(BehaviouralEvidence(auth_records=1)).state == SignalState.NORMAL
    assert classify_auth(BehaviouralEvidence(auth_records=1, failed_logins=3)).state == SignalState.ELEVATED
    assert classify_auth(BehaviouralEvidence(auth_records=1, failed_logins=10)).state == SignalState.HIGH
    assert classify_auth(BehaviouralEvidence(auth_records=1, anomalous_logins=2)).state == SignalState.HIGH
    # 6 telemetry failures + 6 anomaly-reported failures describe overlapping logins: max (6), not sum (12).
    assert classify_auth(BehaviouralEvidence(auth_records=2, failed_logins=6, anomaly_failed_attempts=6)).state == SignalState.ELEVATED
    synthetic = classify_auth(BehaviouralEvidence(auth_records=1, synthetic_records=1))
    assert synthetic.source == Provenance.SYNTHETIC


def test_network_classification() -> None:
    assert classify_network(BehaviouralEvidence()).state == U
    assert classify_network(BehaviouralEvidence(network_records=2)).state == SignalState.NORMAL
    assert classify_network(BehaviouralEvidence(network_records=2, network_alerts=1)).state == SignalState.ELEVATED
    assert classify_network(BehaviouralEvidence(network_records=2, network_alerts=3)).state == SignalState.HIGH


def test_simulation_comparison_uses_same_engine() -> None:
    base = profile(mfa=D, firewall=D, disk_encryption=U)
    proposed_inputs = apply_overrides(base, {"mfa": "enabled", "disk_encryption": "enabled"})
    assert base["mfa"].state == D  # baseline mapping untouched
    baseline, proposed = evaluate("a", base), evaluate("a", proposed_inputs)
    assert proposed.risk_score == evaluate("a", profile(firewall=D)).risk_score
    diff = compare(baseline, proposed)
    assert diff["risk_delta"] == proposed.risk_score - baseline.risk_score < 0
    assert set(diff["resolved_findings"]) == {"mfa_disabled", "disk_encryption_unknown"}
    assert diff["introduced_findings"] == []
    assert {c["key"] for c in diff["changed_signals"]} == {"mfa", "disk_encryption"}
    assert proposed_inputs["mfa"].source == Provenance.HYPOTHETICAL
    with pytest.raises(SignalValidationError):
        apply_overrides(base, {"auth_activity": "normal"})


def test_no_change_simulation_is_identical() -> None:
    base = profile(firewall=D)
    diff = compare(evaluate("a", base), evaluate("a", apply_overrides(base, {"firewall": "disabled"})))
    assert diff["risk_delta"] == 0 and diff["changed_signals"] == []


def test_legacy_flags_translate() -> None:
    inputs = legacy_inputs({"mfa_disabled": True, "firewall_disabled": False, "unknown_device": True})
    assert inputs["mfa"].state == D and inputs["firewall"].state == E and "unknown_device" not in inputs
