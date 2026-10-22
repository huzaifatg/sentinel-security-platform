# API contract

Status: Phase 2 backend foundation. The FastAPI endpoints below are implemented and tested against SQLite; PostgreSQL persistence remains unverified until a running PostgreSQL instance is configured.

## Implemented

### `GET /api/health`

No authentication required.

Response `200`:

```json
{"status":"ok","service":"sentinel-web","version":"0.1.0","checks":{"web":"ok","database":"not_configured","graph":"not_configured"}}
```

The response reports web availability and explicitly identifies unconfigured services. It does not claim database or graph connectivity.

## Implemented API Endpoints

### Identity & Authentication
- `POST /api/v1/auth/register` — user registration with argon2 password hashing.
- `POST /api/v1/auth/login` — OAuth2 password flow returning signed JWT bearer token.
- `GET /api/v1/auth/me` — authenticated identity inspection.

### Device Management & Telemetry
- `POST /api/v1/devices` — register owned device (name, serial number).
- `GET /api/v1/devices` — list authenticated user's registered devices.
- `GET /api/v1/devices/{device_id}` — inspect owned device.
- `POST /api/v1/devices/{device_id}/telemetry` — ingest structured telemetry event.
- `GET /api/v1/devices/{device_id}/telemetry` — list telemetry events for owned device.

### Security Assessment Engine (sentinel-risk-v2)
- `GET /api/v1/risk/methodology` — public endpoint returning formal formula, signal weights, risk factors, severity thresholds, and limitations.
- `GET /api/v1/devices/{device_id}/security-profile` — retrieve configured controls, behavioral evidence summary, and provenance for an owned device.
- `PUT /api/v1/devices/{device_id}/security-profile` — update security controls (MFA as account-level; OS updates, endpoint protection, firewall, disk encryption, screen lock as device-level).
- `POST /api/v1/devices/{device_id}/assessments` — run and persist an authenticated risk assessment with exact score breakdown, findings, and mitigations.
- `GET /api/v1/devices/{device_id}/assessments` — list persisted historical assessments for an owned device.
- `POST /api/v1/risk/assess` — ad-hoc (non-persisted) assessment supporting v2 signals, controls, or legacy v1 boolean flags.

### What-If Risk Simulation
- `POST /api/v1/simulations` — run and persist a what-if comparison between baseline and hypothetical control configurations using the same scoring engine; does not modify stored device state.
- `GET /api/v1/simulations` — retrieve persisted simulation history (optionally filtered by `?device_id=...`).

### Behavioral Anomaly Detection
- `POST /api/v1/anomalies/model/train` — train Isolation Forest model on authentication features.
- `POST /api/v1/anomalies/events` — run anomaly inference on device features and record result.
- `GET /api/v1/anomalies/events` — list anomaly events for owned devices.

