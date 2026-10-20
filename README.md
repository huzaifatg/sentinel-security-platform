# Sentinel

Sentinel is a personal cybersecurity digital twin for security monitoring, explainable risk assessment, and behavioral anomaly detection. It is a university prototype, not a certified security product or replacement for enterprise monitoring.

## Current phase

Phase 2 backend foundation: the FastAPI service, SQLAlchemy models, Alembic initial migration, JWT authentication, ownership authorization, and SQLite-backed API tests are implemented. PostgreSQL remains configurable but is not claimed as verified until tests run against a live PostgreSQL instance.

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`. Verify health with `curl http://localhost:3000/api/health`.

## Planned architecture

- Next.js, React, TypeScript, and CSS for the web application.
- Python/FastAPI, Pydantic, SQLAlchemy, and migrations for authoritative backend logic.
- PostgreSQL for persistent records and Neo4j behind a dedicated graph service.
- pandas, NumPy, and scikit-learn Isolation Forest for reproducible anomaly detection.

See `ARCHITECTURE.md`, `API_CONTRACT.md`, `PROJECT_STATUS.md`, and `HANDOFF.md` for the implementation record.

## Limitations

The current dashboard deliberately uses empty states rather than fabricated scores, devices, alerts, or telemetry. Any future collection must be explicitly authorized and identify whether data is collected or simulated.
