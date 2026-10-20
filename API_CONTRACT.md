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

## Phase 2 backend endpoints

`POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, `POST /api/v1/devices`, `GET /api/v1/devices`, `GET /api/v1/devices/{device_id}`, `POST /api/v1/devices/{device_id}/telemetry`, and `GET /api/v1/devices/{device_id}/telemetry` are implemented with Pydantic validation, bearer authentication, and ownership enforcement.

## Planned

Findings, alerts, recommendations, twin state, anomaly scoring, simulations, and dashboard aggregation remain planned. No UI data is fabricated for these areas.
