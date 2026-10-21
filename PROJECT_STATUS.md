# Project status

- Current phase: Phase 4 — anomaly detection and simulator foundation
- Branch: `v0/phase-1-foundation`; existing Phase 1 work is preserved.
- Completed: FastAPI service, SQLAlchemy user/device/telemetry/anomaly/simulation models, Alembic migrations, Argon2 password hashing, JWT bearer authentication, ownership authorization, validation, deterministic signal-based risk assessment, severity bands, findings, evidence, recommendations, Isolation Forest training/inference, anomaly event persistence, and simulator scenario persistence.
- Verification: the live local dashboard opens and renders, `GET /api/health` returns `status: ok` with database and graph marked `not_configured`, `npm run typecheck`, `npm run lint`, and `npm run build` pass, and `uv run --with-requirements requirements.txt -- python -m pytest backend/test_api.py -q` passes (9 tests). SQLite Alembic upgrade passes; PostgreSQL persistence remains unverified because no running PostgreSQL instance is configured.
- Intentionally deferred: Neo4j, graph enrichment, external integrations, and PostgreSQL production verification.
- Known limitations: SQLite is test-only. Set `DATABASE_URL` and run `alembic upgrade head` against PostgreSQL before claiming production persistence.
- Exact next task: configure a running PostgreSQL test environment and verify migrations, persistence, and auth against it before making production persistence claims. Phase 4 feature work is complete for this checkpoint.
