# Testing record

## Commands

- `npm install` — passed; installed the initial web dependencies. npm reported advisories and a deprecation notice for the selected Next.js version; upgrade before production use.
- `npm run typecheck` — passed.
- `npm run build` — passed with Next.js 16 production output.
- `GET /api/health` — passed; returned `status: ok`, `web: ok`, `database: not_configured`, and `graph: not_configured`.

- `pytest backend/test_api.py` — passed with SQLite-backed registration, login, bearer authentication, ownership enforcement, validation, and telemetry coverage.
- `alembic upgrade head` against a running PostgreSQL instance — not run; PostgreSQL persistence is intentionally unverified in this environment.

The backend tests do not prove PostgreSQL persistence, graph storage, telemetry collection, risk scoring, or ML behavior.
