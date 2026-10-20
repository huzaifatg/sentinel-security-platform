# Project status

- Current phase: Phase 2 — backend foundation
- Branch: `v0/phase-1-foundation`; existing Phase 1 work is preserved.
- Completed: FastAPI service, SQLAlchemy user/device/telemetry models, Alembic initial migration, Argon2 password hashing, JWT bearer authentication, ownership authorization, validation, and SQLite-backed API tests.
- Verification: `pytest backend/test_api.py` passed (2 tests); `DATABASE_URL=sqlite:///./phase2-check.db alembic upgrade head` passed; `curl http://localhost:3000/api/health` returned `status: ok`; `npm run typecheck` and `npm run build` passed. PostgreSQL persistence was not tested because no running PostgreSQL instance is configured.
- Intentionally deferred: telemetry ingestion beyond the core event endpoint, risk engine, recommendations, anomaly model, simulator, Neo4j, and external integrations.
- Known limitations: SQLite is test-only. Set `DATABASE_URL` and run `alembic upgrade head` against PostgreSQL before claiming production persistence.
- Exact next task: configure a running PostgreSQL test environment and verify migrations, persistence, and auth against it before adding risk logic.
