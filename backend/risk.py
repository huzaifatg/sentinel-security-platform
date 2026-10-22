"""Sentinel explainable risk engine — methodology ``sentinel-risk-v2``.

The same pure functions are used by normal assessments and by what-if simulations,
so a baseline and a proposal can never be scored by different rules.

Formula
-------
For every signal *i* with weight ``w_i`` and state-dependent risk factor ``r_i`` in [0, 1]:

    contribution_i = 100 * w_i * r_i / W          (W = sum of weights of applicable signals)
    risk_score     = clamp(round_half_up(sum(contribution_i)), 0, 100)
    security_score = 100 - risk_score

Risk factors: enabled / normal = 0, elevated = 0.5, unknown = 0.5, disabled / high = 1.
``not_applicable`` signals are removed from both the numerator and ``W``.
Unknown is deliberately *not* zero: missing evidence is never treated as verified protection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
from typing import Iterable, Mapping

METHODOLOGY_VERSION = "sentinel-risk-v2"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"


class Provenance(str, Enum):
    """Where a signal value came from. Sentinel never scans a device itself."""

    DEFAULT = "default"  # nothing recorded yet -> always UNKNOWN
    MANUAL = "manual"  # entered by the user
    TELEMETRY = "telemetry"  # derived from telemetry/anomaly records submitted to the API
    SYNTHETIC = "synthetic_demo"  # generated demonstration data, clearly labelled
    MIXED = "mixed"  # behavioural evidence derived from both real and synthetic records
    HYPOTHETICAL = "hypothetical"  # simulation override, never persisted as device state


CONTROL_STATES = (SignalState.ENABLED, SignalState.DISABLED, SignalState.UNKNOWN, SignalState.NOT_APPLICABLE)
BEHAVIOURAL_STATES = (SignalState.NORMAL, SignalState.ELEVATED, SignalState.HIGH, SignalState.UNKNOWN)

UNKNOWN_RISK_FACTOR = 0.5
RISK_FACTOR: dict[SignalState, float] = {
    SignalState.ENABLED: 0.0,
    SignalState.NORMAL: 0.0,
    SignalState.ELEVATED: 0.5,
    SignalState.UNKNOWN: UNKNOWN_RISK_FACTOR,
    SignalState.DISABLED: 1.0,
    SignalState.HIGH: 1.0,
}

# Overall score bands (inclusive upper bounds).
SEVERITY_BANDS: tuple[tuple[int, Severity], ...] = (
    (24, Severity.LOW),
    (49, Severity.MEDIUM),
    (74, Severity.HIGH),
    (100, Severity.CRITICAL),
)
# Per-finding bands on the finding's normalised contribution (points), lower bounds.
FINDING_SEVERITY_FLOORS: tuple[tuple[float, Severity], ...] = (
    (18.0, Severity.CRITICAL),
    (10.0, Severity.HIGH),
    (5.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
)
# An unverified signal is uncertainty, not a confirmed weakness: its finding is capped at medium.
UNKNOWN_FINDING_CAP = Severity.MEDIUM

# Behavioural thresholds over the evidence window.
EVIDENCE_WINDOW_DAYS = 7
FAILED_LOGIN_ELEVATED = 3
FAILED_LOGIN_HIGH = 10
ANOMALOUS_LOGIN_ELEVATED = 1
ANOMALOUS_LOGIN_HIGH = 2
NETWORK_ALERT_ELEVATED = 1
NETWORK_ALERT_HIGH = 3


@dataclass(frozen=True)
class SignalDefinition:
    key: str
    label: str
    scope: str  # "account" | "device" | "behavioral"
    weight: int
    rationale: str
    gap_label: str
    recommendation: str
    unknown_recommendation: str

    @property
    def kind(self) -> str:
        return "behavioral" if self.scope == "behavioral" else "control"

    @property
    def allowed_states(self) -> tuple[SignalState, ...]:
        return BEHAVIOURAL_STATES if self.kind == "behavioral" else CONTROL_STATES


# Weights sum to 100, so with every signal applicable a weight equals its maximum point contribution.
SIGNALS: tuple[SignalDefinition, ...] = (
    SignalDefinition("mfa", "Multi-factor authentication", "account", 20,
                     "Stolen or reused credentials are the most common initial-access vector; MFA blocks most of them.",
                     "MFA disabled on the account", "Enable multi-factor authentication (authenticator app or security key) on the account.",
                     "Confirm whether MFA is enabled on the account and record the result."),
    SignalDefinition("os_updates", "OS & security updates", "device", 18,
                     "Unpatched, publicly known vulnerabilities are routinely exploited.",
                     "Operating system or security updates outstanding", "Install all pending operating system and security updates and enable automatic updates.",
                     "Check the update status of the operating system and record it."),
    SignalDefinition("endpoint_protection", "Endpoint protection", "device", 14,
                     "Anti-malware / EDR detects and blocks malicious code that bypasses other controls.",
                     "Endpoint protection disabled", "Enable real-time endpoint protection (e.g. Microsoft Defender) and keep signatures current.",
                     "Check whether real-time endpoint protection is active and record it."),
    SignalDefinition("firewall", "Host firewall", "device", 12,
                     "Limits unsolicited inbound network access and lateral movement.",
                     "Host firewall disabled", "Enable the host firewall for all network profiles.",
                     "Check the host firewall status and record it."),
    SignalDefinition("disk_encryption", "Full-disk encryption", "device", 12,
                     "Protects data at rest if the device is lost or stolen.",
                     "Full-disk encryption disabled", "Enable full-disk encryption (BitLocker / FileVault / LUKS) and escrow the recovery key.",
                     "Check whether full-disk encryption is enabled and record it."),
    SignalDefinition("screen_lock", "Automatic screen lock", "device", 6,
                     "Reduces opportunistic physical access to an unattended, unlocked session.",
                     "Automatic screen lock disabled", "Enable automatic screen lock after 5 minutes or less of inactivity.",
                     "Check the automatic screen-lock setting and record it."),
    SignalDefinition("auth_activity", "Authentication activity", "behavioral", 12,
                     "Repeated failed logins or model-flagged login patterns can indicate password guessing or account takeover.",
                     "Suspicious authentication activity observed", "Review recent sign-ins, reset the password if any attempt is unrecognised, and confirm MFA is enforced.",
                     "Submit authentication telemetry so login behaviour can be evaluated."),
    SignalDefinition("network_activity", "Network activity", "behavioral", 6,
                     "Unexpected network changes or alerts can indicate compromise or exposure on untrusted networks.",
                     "Unusual network activity observed", "Investigate the flagged connections, avoid untrusted networks, and use a VPN where appropriate.",
                     "Submit network telemetry so network behaviour can be evaluated."),
)
SIGNAL_BY_KEY: dict[str, SignalDefinition] = {signal.key: signal for signal in SIGNALS}
CONTROL_KEYS: tuple[str, ...] = tuple(s.key for s in SIGNALS if s.kind == "control")
DEVICE_CONTROL_KEYS: tuple[str, ...] = tuple(s.key for s in SIGNALS if s.scope == "device")
ACCOUNT_CONTROL_KEYS: tuple[str, ...] = tuple(s.key for s in SIGNALS if s.scope == "account")
BEHAVIOURAL_KEYS: tuple[str, ...] = tuple(s.key for s in SIGNALS if s.kind == "behavioral")


class SignalValidationError(ValueError):
    pass


@dataclass(frozen=True)
class SignalInput:
    state: SignalState
    source: Provenance = Provenance.MANUAL
    evidence: str = ""
    updated_at: datetime | None = None


@dataclass(frozen=True)
class SignalResult:
    key: str
    label: str
    scope: str
    state: SignalState
    source: Provenance
    weight: int
    applicable: bool
    risk_factor: float
    contribution: float
    evidence: str


@dataclass(frozen=True)
class Finding:
    rule: str
    signal: str
    label: str
    category: str  # "control_gap" | "unverified" | "behavioral"
    affected_asset: str
    state: SignalState
    source: Provenance
    evidence: str
    weight: int
    risk_factor: float
    contribution: float
    severity: Severity
    timestamp: datetime
    recommended_action: str


@dataclass(frozen=True)
class Assessment:
    asset_id: str
    methodology_version: str
    risk_score: int
    security_score: int
    severity: Severity
    raw_risk: float
    applicable_weight: int
    coverage: int
    signals: list[SignalResult]
    findings: list[Finding]
    explanation: str
    recommendations: list[str]
    assessed_at: datetime

    def to_dict(self) -> dict:
        return _jsonable(asdict(self))


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def round_half_up(value: float, places: int = 0) -> float:
    quantum = Decimal(1).scaleb(-places)
    return float(Decimal(str(value)).quantize(quantum, rounding=ROUND_HALF_UP))


def severity_for(score: int) -> Severity:
    bounded = max(0, min(100, int(score)))
    for upper, severity in SEVERITY_BANDS:
        if bounded <= upper:
            return severity
    return Severity.CRITICAL


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def finding_severity(contribution: float, state: SignalState) -> Severity:
    severity = next(level for floor, level in FINDING_SEVERITY_FLOORS if contribution >= floor)
    if state == SignalState.UNKNOWN and _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(UNKNOWN_FINDING_CAP):
        return UNKNOWN_FINDING_CAP
    return severity


def parse_state(key: str, value: str | SignalState) -> SignalState:
    definition = SIGNAL_BY_KEY.get(key)
    if definition is None:
        raise SignalValidationError(f"Unsupported signal '{key}'.")
    try:
        state = SignalState(value)
    except ValueError as exc:
        raise SignalValidationError(f"Invalid state '{value}' for signal '{key}'.") from exc
    if state not in definition.allowed_states:
        allowed = ", ".join(item.value for item in definition.allowed_states)
        raise SignalValidationError(f"State '{state.value}' is not valid for '{key}'. Allowed: {allowed}.")
    return state


def _default_evidence(definition: SignalDefinition, signal: SignalInput) -> str:
    if signal.evidence:
        return signal.evidence
    if signal.source == Provenance.DEFAULT:
        return "No value recorded; treated as unverified."
    return f"{definition.label} recorded as '{signal.state.value}' ({signal.source.value})."


def evaluate(asset_id: str, inputs: Mapping[str, SignalInput], observed_at: datetime | None = None) -> Assessment:
    """Score a full signal set. Missing signals are UNKNOWN, never assumed secure."""
    timestamp = observed_at or datetime.now(timezone.utc)
    resolved: dict[str, SignalInput] = {}
    for key, signal in inputs.items():
        parse_state(key, signal.state)  # validates key and state
        resolved[key] = signal
    for definition in SIGNALS:
        resolved.setdefault(definition.key, SignalInput(SignalState.UNKNOWN, Provenance.DEFAULT))

    applicable = [d for d in SIGNALS if resolved[d.key].state != SignalState.NOT_APPLICABLE]
    applicable_weight = sum(d.weight for d in applicable)  # behavioural signals are never N/A, so > 0
    known_weight = sum(d.weight for d in applicable if resolved[d.key].state != SignalState.UNKNOWN)

    signal_results: list[SignalResult] = []
    findings: list[Finding] = []
    raw_total = 0.0
    for definition in SIGNALS:
        signal = resolved[definition.key]
        is_applicable = signal.state != SignalState.NOT_APPLICABLE
        factor = RISK_FACTOR.get(signal.state, 0.0) if is_applicable else 0.0
        exact = 100.0 * definition.weight * factor / applicable_weight if is_applicable else 0.0
        raw_total += exact
        contribution = round_half_up(exact, 1)
        evidence = _default_evidence(definition, signal)
        signal_results.append(SignalResult(definition.key, definition.label, definition.scope, signal.state, signal.source,
                                           definition.weight, is_applicable, factor, contribution, evidence))
        if factor <= 0:
            continue
        if signal.state == SignalState.UNKNOWN:
            category, label, action = "unverified", f"{definition.label} not verified", definition.unknown_recommendation
        elif definition.kind == "behavioral":
            category, label, action = "behavioral", definition.gap_label, definition.recommendation
        else:
            category, label, action = "control_gap", definition.gap_label, definition.recommendation
        findings.append(Finding(f"{definition.key}_{signal.state.value}", definition.key, label, category, asset_id, signal.state,
                                signal.source, evidence, definition.weight, factor, contribution,
                                finding_severity(contribution, signal.state), timestamp, action))

    raw_risk = round_half_up(raw_total, 2)
    risk_score = int(max(0, min(100, round_half_up(raw_total))))
    severity = severity_for(risk_score)
    coverage = int(round_half_up(100.0 * known_weight / applicable_weight))
    findings.sort(key=lambda item: (-item.contribution, item.signal))
    weighted_sum = round_half_up(sum(d.weight * RISK_FACTOR.get(resolved[d.key].state, 0.0) for d in applicable), 2)
    excluded = [d.label for d in SIGNALS if d not in applicable]
    explanation = (
        f"Risk = 100 x sum(weight x factor) / applicable weight = 100 x {weighted_sum:g} / {applicable_weight} "
        f"= {raw_risk:g}, rounded to {risk_score}/100 ({severity.value}). Security score = 100 - risk = {100 - risk_score}. "
        f"{len(findings)} finding(s) contribute risk; evidence coverage is {coverage}% of applicable weight."
        + (f" Excluded as not applicable: {', '.join(excluded)}." if excluded else "")
    )
    recommendations = [item.recommended_action for item in findings[:5]]
    return Assessment(asset_id, METHODOLOGY_VERSION, risk_score, 100 - risk_score, severity, raw_risk, applicable_weight,
                      coverage, signal_results, findings, explanation, recommendations, timestamp)


# ---------------------------------------------------------------------------
# Behavioural evidence classification
# ---------------------------------------------------------------------------

@dataclass
class BehaviouralEvidence:
    """Counts derived from records submitted to the API inside the evidence window."""

    auth_records: int = 0
    failed_logins: int = 0
    anomalous_logins: int = 0
    anomaly_failed_attempts: int = 0
    network_records: int = 0
    network_alerts: int = 0
    anomaly_network_flags: int = 0
    real_records: int = 0
    synthetic_records: int = 0
    window_days: int = EVIDENCE_WINDOW_DAYS
    notes: list[str] = field(default_factory=list)

    @property
    def source(self) -> Provenance:
        if self.real_records and self.synthetic_records:
            return Provenance.MIXED
        if self.synthetic_records:
            return Provenance.SYNTHETIC
        return Provenance.TELEMETRY


def classify_auth(evidence: BehaviouralEvidence) -> SignalInput:
    if evidence.auth_records == 0:
        return SignalInput(SignalState.UNKNOWN, Provenance.DEFAULT,
                           f"No authentication telemetry or anomaly events in the last {evidence.window_days} days.")
    # Failed attempts reported by telemetry and by anomaly features may describe the same logins,
    # so take the maximum rather than the sum to avoid double counting.
    failed = max(evidence.failed_logins, evidence.anomaly_failed_attempts)
    anomalous = evidence.anomalous_logins
    if failed >= FAILED_LOGIN_HIGH or anomalous >= ANOMALOUS_LOGIN_HIGH:
        state = SignalState.HIGH
    elif failed >= FAILED_LOGIN_ELEVATED or anomalous >= ANOMALOUS_LOGIN_ELEVATED:
        state = SignalState.ELEVATED
    else:
        state = SignalState.NORMAL
    text = (f"{failed} failed login attempt(s) and {anomalous} model-flagged anomalous login(s) across "
            f"{evidence.auth_records} record(s) in the last {evidence.window_days} days "
            f"(elevated at >= {FAILED_LOGIN_ELEVATED} failures or >= {ANOMALOUS_LOGIN_ELEVATED} anomaly; "
            f"high at >= {FAILED_LOGIN_HIGH} failures or >= {ANOMALOUS_LOGIN_HIGH} anomalies).")
    return SignalInput(state, evidence.source, text)


def classify_network(evidence: BehaviouralEvidence) -> SignalInput:
    if evidence.network_records == 0:
        return SignalInput(SignalState.UNKNOWN, Provenance.DEFAULT,
                           f"No network telemetry or anomaly events in the last {evidence.window_days} days.")
    alerts = max(evidence.network_alerts, evidence.anomaly_network_flags)
    if alerts >= NETWORK_ALERT_HIGH:
        state = SignalState.HIGH
    elif alerts >= NETWORK_ALERT_ELEVATED:
        state = SignalState.ELEVATED
    else:
        state = SignalState.NORMAL
    text = (f"{alerts} unusual network event(s) across {evidence.network_records} record(s) in the last "
            f"{evidence.window_days} days (elevated at >= {NETWORK_ALERT_ELEVATED}, high at >= {NETWORK_ALERT_HIGH}).")
    return SignalInput(state, evidence.source, text)


# ---------------------------------------------------------------------------
# Simulation comparison
# ---------------------------------------------------------------------------

def apply_overrides(inputs: Mapping[str, SignalInput], overrides: Mapping[str, str | SignalState]) -> dict[str, SignalInput]:
    proposed = dict(inputs)
    for key, value in overrides.items():
        definition = SIGNAL_BY_KEY.get(key)
        if definition is None or definition.kind != "control":
            raise SignalValidationError(f"Only security controls can be simulated; '{key}' is not a control.")
        state = parse_state(key, value)
        current = inputs.get(key)
        if current is not None and current.state == state:
            continue
        proposed[key] = SignalInput(state, Provenance.HYPOTHETICAL, f"Hypothetical: {definition.label} set to '{state.value}'.")
    return proposed


def compare(baseline: Assessment, proposed: Assessment) -> dict:
    before = {s.key: s for s in baseline.signals}
    after = {s.key: s for s in proposed.signals}
    changed = [
        {"key": key, "label": after[key].label, "from_state": before[key].state.value, "to_state": after[key].state.value,
         "contribution_before": before[key].contribution, "contribution_after": after[key].contribution,
         "delta": round_half_up(after[key].contribution - before[key].contribution, 1)}
        for key in SIGNAL_BY_KEY if before[key].state != after[key].state
    ]
    before_rules = {f.rule: f for f in baseline.findings}
    after_rules = {f.rule: f for f in proposed.findings}
    resolved = sorted(set(before_rules) - set(after_rules))
    introduced = sorted(set(after_rules) - set(before_rules))
    delta = proposed.risk_score - baseline.risk_score
    if not changed:
        why = "No control changed, so the proposed configuration scores identically to the baseline."
    else:
        parts = [f"{c['label']} {c['from_state']} -> {c['to_state']} ({c['delta']:+g} pts)" for c in changed]
        direction = "decreases" if delta < 0 else "increases" if delta > 0 else "does not change"
        why = (f"Risk {direction} from {baseline.risk_score} to {proposed.risk_score} ({delta:+d}) because: " + "; ".join(parts)
               + ". Both configurations were scored by the same weighted formula.")
        if baseline.applicable_weight != proposed.applicable_weight:
            why += (f" Applicable weight changed from {baseline.applicable_weight} to {proposed.applicable_weight}, "
                    "so every remaining contribution was renormalised.")
    return {
        "risk_delta": delta,
        "security_delta": proposed.security_score - baseline.security_score,
        "changed_signals": changed,
        "resolved_findings": resolved,
        "introduced_findings": introduced,
        "explanation": why,
        "recommendations": proposed.recommendations[:3],
    }


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------

LEGACY_SIGNAL_MAP: dict[str, tuple[str, SignalState, SignalState]] = {
    # legacy key: (signal, state when True, state when False)
    "mfa_disabled": ("mfa", SignalState.DISABLED, SignalState.ENABLED),
    "firewall_disabled": ("firewall", SignalState.DISABLED, SignalState.ENABLED),
    "operating_system_outdated": ("os_updates", SignalState.DISABLED, SignalState.ENABLED),
    "disk_encryption_disabled": ("disk_encryption", SignalState.DISABLED, SignalState.ENABLED),
    "unusual_login": ("auth_activity", SignalState.HIGH, SignalState.NORMAL),
}
LEGACY_CHANGE_MAP: dict[str, str] = {
    "mfa_enabled": "mfa",
    "operating_system_updated": "os_updates",
    "firewall_enabled": "firewall",
    "disk_encryption_enabled": "disk_encryption",
}


def legacy_inputs(signals: Mapping[str, bool]) -> dict[str, SignalInput]:
    """Translate v1 boolean flags. Unsupported keys (e.g. ``unknown_device``) are ignored."""
    result: dict[str, SignalInput] = {}
    for legacy_key, flag in signals.items():
        mapping = LEGACY_SIGNAL_MAP.get(legacy_key)
        if mapping:
            key, when_true, when_false = mapping
            result[key] = SignalInput(when_true if flag else when_false, Provenance.MANUAL, f"signal:{legacy_key}={str(flag).lower()}")
    return result


def methodology() -> dict:
    return {
        "version": METHODOLOGY_VERSION,
        "formula": "risk = clamp(round_half_up(100 * sum(w_i * r_i) / sum(w_j for applicable j)), 0, 100); security = 100 - risk",
        "risk_factors": {state.value: factor for state, factor in RISK_FACTOR.items()},
        "not_applicable": "Excluded from numerator and denominator (weights renormalised).",
        "unknown_policy": f"Unknown evidence carries factor {UNKNOWN_RISK_FACTOR}: never treated as verified protection.",
        "signals": [{"key": s.key, "label": s.label, "scope": s.scope, "kind": s.kind, "weight": s.weight, "rationale": s.rationale,
                     "allowed_states": [state.value for state in s.allowed_states]} for s in SIGNALS],
        "severity_bands": [{"max_score": upper, "severity": severity.value} for upper, severity in SEVERITY_BANDS],
        "finding_severity_floors": [{"min_points": floor, "severity": severity.value} for floor, severity in FINDING_SEVERITY_FLOORS],
        "unknown_finding_cap": UNKNOWN_FINDING_CAP.value,
        "behavioral_thresholds": {
            "window_days": EVIDENCE_WINDOW_DAYS,
            "auth_activity": {"elevated": f">= {FAILED_LOGIN_ELEVATED} failed logins or >= {ANOMALOUS_LOGIN_ELEVATED} anomalous login",
                              "high": f">= {FAILED_LOGIN_HIGH} failed logins or >= {ANOMALOUS_LOGIN_HIGH} anomalous logins"},
            "network_activity": {"elevated": f">= {NETWORK_ALERT_ELEVATED} unusual network event", "high": f">= {NETWORK_ALERT_HIGH} unusual network events"},
        },
        "limitations": [
            "Control states are user-reported or synthetic demonstration data; Sentinel does not scan devices.",
            "Weights are expert-assigned relative priorities, not empirically calibrated probabilities.",
            "Behavioural signals only reflect telemetry and anomaly events submitted to the API.",
        ],
    }


def aggregate(scores: Iterable[int]) -> int:
    """Environment score is the capped sum of distinct asset contributions, not an average."""
    return min(100, sum(max(0, score) for score in scores))
