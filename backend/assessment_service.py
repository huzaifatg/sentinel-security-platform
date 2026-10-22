"""Database-facing helpers for the risk engine: stored controls, behavioural evidence, profiles."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AnomalyEvent, Device, TelemetryEvent, User
from .risk import (
    ACCOUNT_CONTROL_KEYS,
    BEHAVIOURAL_KEYS,
    DEVICE_CONTROL_KEYS,
    EVIDENCE_WINDOW_DAYS,
    SIGNALS,
    BehaviouralEvidence,
    Provenance,
    SignalInput,
    SignalState,
    SignalValidationError,
    classify_auth,
    classify_network,
    parse_state,
)

# Telemetry conventions understood by the engine (other event types are stored but not scored).
AUTH_FAILURE_EVENTS = {"auth_failure", "login_failed"}
AUTH_SUCCESS_EVENTS = {"auth_success", "login_success"}
NETWORK_ALERT_EVENTS = {"network_alert"}
NETWORK_NORMAL_EVENTS = {"network_summary"}
MAX_EVENT_COUNT = 1000


def _load(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _stored_inputs(raw: str | None, keys: tuple[str, ...]) -> dict[str, SignalInput]:
    stored = _load(raw)
    result: dict[str, SignalInput] = {}
    for key in keys:
        entry = stored.get(key)
        if not isinstance(entry, dict):
            continue
        try:
            state = parse_state(key, entry.get("state", "unknown"))
            source = Provenance(entry.get("source", Provenance.MANUAL.value))
        except (SignalValidationError, ValueError):
            continue  # corrupt entries degrade to unknown rather than to "secure"
        result[key] = SignalInput(state, source, updated_at=_parse_time(entry.get("updated_at")))
    return result


def stored_control_inputs(user: User, device: Device) -> dict[str, SignalInput]:
    inputs = _stored_inputs(user.account_controls, ACCOUNT_CONTROL_KEYS)
    inputs.update(_stored_inputs(device.security_controls, DEVICE_CONTROL_KEYS))
    return inputs


def update_controls(user: User, device: Device, controls: Mapping[str, SignalState | str], source: Provenance) -> None:
    if source not in (Provenance.MANUAL, Provenance.SYNTHETIC):
        raise SignalValidationError("Stored controls must be 'manual' or 'synthetic_demo'.")
    account = _load(user.account_controls)
    device_controls = _load(device.security_controls)
    now = datetime.now(timezone.utc).isoformat()
    for key, value in controls.items():
        if key in BEHAVIOURAL_KEYS:
            raise SignalValidationError(f"'{key}' is derived from telemetry and cannot be set manually.")
        state = parse_state(key, value)
        entry = {"state": state.value, "source": source.value, "updated_at": now}
        if key in ACCOUNT_CONTROL_KEYS:
            account[key] = entry
        else:
            device_controls[key] = entry
    user.account_controls = json.dumps(account)
    device.security_controls = json.dumps(device_controls)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _count(payload: dict[str, Any]) -> int:
    raw = payload.get("count", 1)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 1
    return max(1, min(MAX_EVENT_COUNT, int(raw)))


def gather_evidence(db: Session, device: Device, now: datetime | None = None) -> BehaviouralEvidence:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=EVIDENCE_WINDOW_DAYS)
    evidence = BehaviouralEvidence()

    for event in db.scalars(select(TelemetryEvent).where(TelemetryEvent.device_id == device.id)).all():
        if event.observed_at is None or _as_utc(event.observed_at) < cutoff:
            continue
        payload = _load(event.payload)
        kind = event.event_type
        is_login = kind == "login" and isinstance(payload.get("success"), bool)
        relevant = True
        if kind in AUTH_FAILURE_EVENTS or (is_login and payload["success"] is False):
            evidence.auth_records += 1
            evidence.failed_logins += _count(payload)
        elif kind in AUTH_SUCCESS_EVENTS or (is_login and payload["success"] is True):
            evidence.auth_records += 1
        elif kind in NETWORK_ALERT_EVENTS:
            evidence.network_records += 1
            evidence.network_alerts += _count(payload)
        elif kind in NETWORK_NORMAL_EVENTS:
            evidence.network_records += 1
        else:
            relevant = False
        if relevant:
            if payload.get("source") == Provenance.SYNTHETIC.value:
                evidence.synthetic_records += 1
            else:
                evidence.real_records += 1

    for event in db.scalars(select(AnomalyEvent).where(AnomalyEvent.device_id == device.id)).all():
        if event.observed_at is None or _as_utc(event.observed_at) < cutoff:
            continue
        features = _load(event.features)
        evidence.auth_records += 1
        evidence.network_records += 1
        attempts = features.get("failed_attempts", 0)
        if isinstance(attempts, (int, float)) and not isinstance(attempts, bool):
            evidence.anomaly_failed_attempts += max(0, int(attempts))
        if event.is_anomaly:
            evidence.anomalous_logins += 1
            if features.get("network_change") is True:
                evidence.anomaly_network_flags += 1
        if event.source == "simulated":
            evidence.synthetic_records += 1
        else:
            evidence.real_records += 1
    return evidence


def device_inputs(db: Session, user: User, device: Device) -> tuple[dict[str, SignalInput], BehaviouralEvidence]:
    inputs = stored_control_inputs(user, device)
    evidence = gather_evidence(db, device)
    inputs["auth_activity"] = classify_auth(evidence)
    inputs["network_activity"] = classify_network(evidence)
    return inputs, evidence


def profile_payload(device: Device, inputs: Mapping[str, SignalInput], evidence: BehaviouralEvidence) -> dict[str, Any]:
    signals = []
    for definition in SIGNALS:
        signal = inputs.get(definition.key) or SignalInput(SignalState.UNKNOWN, Provenance.DEFAULT)
        signals.append({
            "key": definition.key, "label": definition.label, "scope": definition.scope, "kind": definition.kind,
            "weight": definition.weight, "state": signal.state, "source": signal.source, "updated_at": signal.updated_at,
            "evidence": signal.evidence, "allowed_states": list(definition.allowed_states),
        })
    return {
        "device_id": device.id,
        "signals": signals,
        "evidence_window_days": evidence.window_days,
        "behavioral_evidence": {
            "auth_records": evidence.auth_records, "failed_logins": evidence.failed_logins,
            "anomalous_logins": evidence.anomalous_logins, "anomaly_failed_attempts": evidence.anomaly_failed_attempts,
            "network_records": evidence.network_records, "network_alerts": evidence.network_alerts,
            "anomaly_network_flags": evidence.anomaly_network_flags, "real_records": evidence.real_records,
            "synthetic_records": evidence.synthetic_records,
        },
    }
