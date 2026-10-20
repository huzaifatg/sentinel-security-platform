# Testing record

## Commands

- `npm install` — passed; installed the initial web dependencies. npm reported advisories and a deprecation notice for the selected Next.js version; upgrade before production use.
- `npm run typecheck` — passed.
- `npm run build` — passed with Next.js 16 production output.
- `GET /api/health` — passed in the live local preview; returned `status: ok`, `service: sentinel-web`, `version: 0.1.0`, `web: ok`, `database: not_configured`, and `graph: not_configured`.
- `vercel inspect ... --logs` — the previous deployment built successfully, then Vercel blocked deployment because `next@16.0.0` was vulnerable. Updated to `next@16.4.2`; local production build passes. A new production deployment has not yet been run, so deployment remains unverified.

- `uv run --with-requirements requirements.txt -- python -m pytest backend/test_api.py -q` — passed: 6 tests covering SQLite-backed registration, login, bearer authentication, ownership enforcement, validation, telemetry, risk score caps, severity boundaries, deduplication, unknown-signal handling, and evidence.
- `alembic upgrade head` against a running PostgreSQL instance — not run; PostgreSQL persistence is intentionally unverified in this environment.

The backend tests do not prove PostgreSQL persistence, graph storage, telemetry collection, risk scoring, or ML behavior.
