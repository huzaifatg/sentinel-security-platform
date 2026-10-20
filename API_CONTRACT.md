# API contract

Status: foundation only. Implemented endpoints are listed below; all domain endpoints are planned and must not be represented as live UI data.

## Implemented

### `GET /api/health`

No authentication required.

Response `200`:

```json
{"status":"ok","service":"sentinel-web","version":"0.1.0","checks":{"web":"ok","database":"not_configured","graph":"not_configured"}}
```

The response reports web availability and explicitly identifies unconfigured services. It does not claim database or graph connectivity.

## Planned

`/api/v1/auth`, `/api/v1/devices`, `/api/v1/telemetry`, `/api/v1/findings`, `/api/v1/alerts`, `/api/v1/recommendations`, `/api/v1/twin`, `/api/v1/anomalies`, `/api/v1/simulations`, and `/api/v1/dashboard` will be added with Pydantic schemas, pagination where needed, ownership enforcement, and documented error responses.
