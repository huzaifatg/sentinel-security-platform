# Sentinel Risk Assessment Methodology (sentinel-risk-v2)

This document specifies the exact scoring methodology, mathematical formulation, weights, thresholds, and evidence models implemented in Sentinel's security assessment and simulation engine.

---

## 1. Executive Summary & Purpose

Sentinel functions as a **Personal Cybersecurity Digital Twin**. Rather than relying on simple binary toggles or opaque heuristic scores, Sentinel implements a deterministic, evidence-based, explainable risk scoring system (`sentinel-risk-v2`).

Key properties:
- **Deterministic**: Identical inputs always produce identical scores.
- **Explainable**: Every point of risk is traceable to a specific signal, weight, risk factor, and evidence string.
- **Monotonic**: Enabling a protective control never increases risk; disabling a protective control never reduces risk.
- **Bounded**: Risk and security scores are strictly bounded within `[0, 100]`.
- **Honest Uncertainty**: Missing data is explicitly classified as `unknown` and assigned an uncertainty risk factor ($0.5$). Lack of evidence is never falsely counted as verified protection.
- **Unified Engine**: Real assessments and what-if simulations share the exact same evaluation algorithm.

---

## 2. Mathematical Formulation

### 2.1 Core Formula

For any evaluated asset (device and associated account), let $\mathcal{S}$ denote the set of all supported security signals.

Each signal $i \in \mathcal{S}$ has:
- A predefined integer weight $w_i \in \mathbb{N}^+$, where $\sum_{i \in \mathcal{S}} w_i = 100$.
- A state $s_i \in \{\text{enabled}, \text{disabled}, \text{unknown}, \text{not\_applicable}, \text{normal}, \text{elevated}, \text{high}\}$.
- A risk factor $r_i \in [0.0, 1.0]$ determined by its state.

Signals marked `not_applicable` are excluded from evaluation. Let $\mathcal{A} \subseteq \mathcal{S}$ be the set of **applicable** signals:
$$\mathcal{A} = \{ i \in \mathcal{S} \mid s_i \neq \text{not\_applicable} \}$$

The total applicable weight $W_{\mathcal{A}}$ is:
$$W_{\mathcal{A}} = \sum_{i \in \mathcal{A}} w_i$$

The normalized risk contribution $C_i$ (in points) for signal $i \in \mathcal{A}$ is:
$$C_i = 100 \times \frac{w_i \times r_i}{W_{\mathcal{A}}}$$

The raw total risk $R_{\text{raw}}$ is:
$$R_{\text{raw}} = \sum_{i \in \mathcal{A}} C_i = 100 \times \frac{\sum_{i \in \mathcal{A}} w_i \times r_i}{W_{\mathcal{A}}}$$

The integer **Risk Score** $R \in [0, 100]$ is computed using half-up rounding:
$$R = \text{clamp}\left( \text{round\_half\_up}(R_{\text{raw}}), 0, 100 \right)$$

The **Security Score** $S \in [0, 100]$ is consistently derived as the complement:
$$S = 100 - R$$

### 2.2 Evidence Coverage

The **Evidence Coverage** represents the percentage of applicable weight that has been verified with known evidence:
$$\text{Coverage} = \text{round\_half\_up}\left( 100 \times \frac{\sum_{i \in \mathcal{A}, s_i \neq \text{unknown}} w_i}{W_{\mathcal{A}}} \right)$$

---

## 3. Supported Security Signals & Weights

The weights sum to $100$. When all signals are applicable, a signal's weight directly equals its maximum potential risk contribution.

| Key | Signal Name | Scope | Kind | Weight | Rationale |
|---|---|---|---|:---:|---|
| `mfa` | Multi-Factor Authentication | Account | Control | **20** | Credential theft and reuse are the primary initial access vectors; account-level MFA blocks over 99% of automated credential stuffing attacks. |
| `os_updates` | OS & Security Updates | Device | Control | **18** | Known, unpatched software vulnerabilities (CVEs) are routinely targeted by exploit kits and automated scanners. |
| `endpoint_protection` | Real-Time Endpoint Protection | Device | Control | **14** | Anti-malware and behavioral detection guard against malicious binaries, ransomware, and drive-by downloads. |
| `firewall` | Host Firewall | Device | Control | **12** | Restricts unsolicited inbound network connections and mitigates unauthorized lateral movement. |
| `disk_encryption` | Full-Disk Encryption | Device | Control | **12** | Protects data-at-rest confidentiality if the physical device is lost, stolen, or improperly decommissioned. |
| `screen_lock` | Automatic Screen Lock | Device | Control | **6** | Mitigates opportunistic physical access to unattended, unlocked interactive sessions. |
| `auth_activity` | Authentication Activity | Behavioral | Telemetry | **12** | Repeated failed logins or ML-flagged anomalies indicate brute-force password guessing or unauthorized token reuse. |
| `network_activity` | Network Activity | Behavioral | Telemetry | **6** | Unexpected network changes or suspicious connection alerts indicate potential C2 traffic or insecure public network exposure. |
| **Total** | | | | **100** | |

---

## 4. State Representation & Risk Factors

| State | Category | Risk Factor ($r_i$) | Interpretation |
|---|---|:---:|---|
| `enabled` | Control | **0.0** | Protective control verified active. Zero risk penalty. |
| `normal` | Behavioral | **0.0** | Observed activity within normal baseline parameters. Zero risk penalty. |
| `elevated` | Behavioral | **0.5** | Minor anomaly or moderate failure volume observed. |
| `unknown` | Both | **0.5** | No evidence recorded. Treated as unverified risk. |
| `disabled` | Control | **1.0** | Protective control verified inactive. Full risk penalty. |
| `high` | Behavioral | **1.0** | Significant anomaly or heavy failed-attempt spike detected. |
| `not_applicable` | Control | *Excluded* | Control not relevant to this asset (renormalizes remaining weights). |

> **Important**: `unknown` carries a risk factor of $0.5$. Missing data is never treated as evidence of safety.

---

## 5. Severity Thresholds

### 5.1 Overall Score Severity Bands
The overall score is mapped into four standardized severity tiers:

| Score Range | Severity Tier | Meaning |
|:---:|:---:|---|
| **0 – 24** | **Low** | Strong security posture. Core protective controls active; baseline activity normal. |
| **25 – 49** | **Medium** | Moderate security gaps or multiple unverified signals. Remediation advised. |
| **50 – 74** | **High** | Critical protective controls disabled or elevated behavioral anomalies present. |
| **75 – 100** | **Critical** | Severe vulnerabilities, disabled defenses, and active high-threat indicators. |

### 5.2 Finding Severity Floors
Individual findings receive severity based on their normalized point contribution:

| Normalized Contribution | Finding Severity |
|:---:|:---:|
| $\ge 18.0\text{ pts}$ | **Critical** |
| $\ge 10.0\text{ pts}$ | **High** |
| $\ge 5.0\text{ pts}$ | **Medium** |
| $< 5.0\text{ pts}$ | **Low** |

*Special Rule*: Findings generated solely due to `unknown` state are capped at **Medium** severity because uncertainty represents incomplete visibility rather than confirmed malicious exploitation or disabled protection.

---

## 6. Behavioral Signal Classification

Behavioral signals are evaluated dynamically from telemetry events (`telemetry_events`) and Isolation Forest anomaly records (`anomaly_events`) submitted within a rolling **7-day window**.

### 6.1 Authentication Activity (`auth_activity`)
- **Telemetry Event Types**: `auth_failure`, `auth_success`, `login`.
- **Anomaly Detection Integration**: Counts `failed_attempts` and flags `is_anomaly` from Isolation Forest inference.
- **De-duplication**: To prevent double-counting between raw authentication logs and model features describing the same logins, Sentinel computes:
  $$\text{Failed} = \max(\text{telemetry\_failures}, \text{anomaly\_failed\_attempts})$$
- **Classification Rules**:
  - `high`: $\text{Failed} \ge 10$ OR $\text{Anomalous Logins} \ge 2$.
  - `elevated`: $\text{Failed} \ge 3$ OR $\text{Anomalous Logins} \ge 1$.
  - `normal`: $\ge 1$ authentication record, below elevated thresholds.
  - `unknown`: 0 records in 7-day window.

### 6.2 Network Activity (`network_activity`)
- **Telemetry Event Types**: `network_alert`, `network_summary`.
- **Anomaly Detection Integration**: Flagged network changes during anomalous logins.
- **Classification Rules**:
  - `high`: $\ge 3$ network alerts.
  - `elevated`: $\ge 1$ network alert.
  - `normal`: $\ge 1$ network record, 0 alerts.
  - `unknown`: 0 records in 7-day window.

---

## 7. What-If Security Simulation

The simulation engine allows users to model hypothetical configuration changes without mutating the device's actual stored settings.

### 7.1 Principles
1. **Engine Invariance**: The baseline profile and the hypothetical profile are evaluated using the identical `evaluate()` function.
2. **Non-Mutating**: Stored configuration in `users` and `devices` tables remains completely unmodified.
3. **Persisted History**: Simulation runs are recorded in `simulation_records` with full comparison details, enabling historical auditing.
4. **Behavioral Preservation**: Behavioral signals reflect empirical observation; therefore, what-if simulations evaluate modifications to security controls (`mfa`, `firewall`, `os_updates`, `endpoint_protection`, `disk_encryption`, `screen_lock`).

### 7.2 Comparison Metrics
For any simulation, Sentinel computes:
- $\Delta\text{Risk} = R_{\text{proposed}} - R_{\text{baseline}}$
- $\Delta\text{Security} = S_{\text{proposed}} - S_{\text{baseline}}$
- **Resolved Findings**: $\{ f \in \text{Findings}_{\text{baseline}} \setminus \text{Findings}_{\text{proposed}} \}$
- **Introduced Findings**: $\{ f \in \text{Findings}_{\text{proposed}} \setminus \text{Findings}_{\text{baseline}} \}$
- **Per-Control Delta**: Exact change in points for each altered signal.
- **Plain-English Explanation**: Automated narrative explaining the directional change and the exact controls responsible.

---

## 8. Data Provenance & Transparency

Every signal in Sentinel explicitly records its data provenance:
- `manual`: Configured directly by the user via the UI.
- `telemetry`: Derived from events submitted to `/api/v1/devices/{id}/telemetry`.
- `synthetic_demo`: Clearly labeled demonstration data populated for evaluation.
- `mixed`: Behavioral signal combining telemetry and synthetic data.
- `hypothetical`: Simulation override; never persisted as device state.
- `default`: No record exists; evaluated as `unknown`.

---

## 9. Assumptions & Limitations

1. **No Agent Scanning**: Sentinel is an analytical digital twin platform. It does not run background OS daemons or execute kernel-level audits; control states are reported by authenticated users or telemetry collectors.
2. **Relative Weighting**: Weights represent expert-calibrated relative priorities aligned with CIS Benchmarks and NIST SP 800-53, rather than empirical actuarial loss data.
3. **Telemetry Completeness**: Behavioral anomaly detection is bounded by the telemetry submitted through the API.
