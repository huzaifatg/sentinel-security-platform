from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskRule:
    key: str
    label: str
    contribution: int
    recommendation: str


RULES = {
    "disk_encryption_disabled": RiskRule("disk_encryption_disabled", "Disk encryption disabled", 25, "Enable full-disk encryption."),
    "unusual_login": RiskRule("unusual_login", "Unusual login", 20, "Review the login and revoke unrecognized sessions."),
    "firewall_disabled": RiskRule("firewall_disabled", "Firewall disabled", 15, "Enable the host firewall."),
    "operating_system_outdated": RiskRule("operating_system_outdated", "Operating system outdated", 15, "Install supported operating system updates."),
    "mfa_disabled": RiskRule("mfa_disabled", "MFA disabled", 15, "Enable multi-factor authentication."),
    "unknown_device": RiskRule("unknown_device", "Unknown device", 10, "Verify device ownership before granting access."),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    label: str
    affected_asset: str
    evidence: str
    contribution: int
    severity: Severity
    timestamp: datetime
    recommended_action: str


def severity_for(score: int) -> Severity:
    if score <= 30:
        return Severity.LOW
    if score <= 60:
        return Severity.MEDIUM
    if score <= 80:
        return Severity.HIGH
    return Severity.CRITICAL


def assess(asset_id: str, signals: dict[str, bool], observed_at: datetime | None = None) -> tuple[int, list[Finding]]:
    timestamp = observed_at or datetime.now(timezone.utc)
    active: list[Finding] = []
    seen: set[str] = set()
    for key, enabled in signals.items():
        if not enabled or key in seen or key not in RULES:
            continue
        seen.add(key)
        rule = RULES[key]
        active.append(Finding(key, rule.label, asset_id, f"signal:{key}=true", rule.contribution, Severity.LOW, timestamp, rule.recommendation))
    score = min(100, sum(item.contribution for item in active))
    severity = severity_for(score)
    return score, [Finding(item.rule, item.label, item.affected_asset, item.evidence, item.contribution, severity, item.timestamp, item.recommended_action) for item in active]


def aggregate(scores: Iterable[int]) -> int:
    """Environment score is the capped sum of distinct asset contributions, not an average."""
    return min(100, sum(max(0, score) for score in scores))
