# Project status

- Current phase: Phase 3 — risk engine and findings
- Branch: `v0/phase-1-foundation`; existing Phase 1 work is preserved.
- Completed: FastAPI service, SQLAlchemy user/device/telemetry models, Alembic initial migration, Argon2 password hashing, JWT bearer authentication, ownership authorization, validation, SQLite-backed API tests, deterministic signal-based risk assessment, severity bands, findings, evidence, and recommendations.
- Verification: `npm run typecheck` and `npm run build` pass. Backend test execution is blocked in the current shell because `pytest` is not installed; no backend test result is claimed. PostgreSQL persistence remains unverified because no running PostgreSQL instance is configured.
- Intentionally deferred: persisted findings/alerts, anomaly model, simulator, Neo4j, frontend data wiring, and external integrations.
- Known limitations: SQLite is test-only. Set `DATABASE_URL` and run `alembic upgrade head` against PostgreSQL before claiming production persistence.
- Exact next task: configure a running PostgreSQL test environment and verify migrations, persistence, and auth against it before adding risk logic.
