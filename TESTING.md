# Testing record

## Commands

- `npm install` — passed; installed the initial web dependencies. npm reported advisories and a deprecation notice for the selected Next.js version; upgrade before production use.
- `npm run typecheck` — passed.
- `npm run build` — passed with Next.js 16 production output.
- `GET /api/health` — passed in the live local preview; returned `status: ok`, `service: sentinel-web`, `version: 0.1.0`, `web: ok`, `database: not_configured`, and `graph: not_configured`.
- `vercel inspect ... --logs` — the previous deployment built successfully, then Vercel blocked deployment because `next@16.0.0` was vulnerable. Updated to `next@16.4.2`; local production build passes. A new production deployment has not yet been run, so deployment remains unverified.

- `uv run --with-requirements requirements.txt -- python -m pytest backend/test_api.py -q` — passed: 6 tests covering SQLite-backed registration, login, bearer authentication, ownership enforcement, validation, telemetry, risk score caps, severity boundaries, deduplication, unknown-signal handling, and evidence.
- `alembic upgrade head` against a running PostgreSQL instance — not run; PostgreSQL persistence is intentionally unverified in this environment.

Phase 4 checks: `uv run --with scikit-learn --with joblib python -m compileall backend migrations` — passed. `uv run --with-requirements requirements.txt -- python -m pytest backend/test_api.py -q` — passed: 9 tests, including anomaly training/inference, evidence serialization, simulator determinism/non-mutation, and cross-user ownership. `uv run --with-requirements requirements.txt -- alembic upgrade head` — passed against the configured SQLite test database. `npm run typecheck` — passed. `npm run build` — passed. PostgreSQL integration and production deployment remain unverified.

The backend tests do not prove PostgreSQL persistence, graph storage, telemetry collection, risk scoring, or ML behavior.
