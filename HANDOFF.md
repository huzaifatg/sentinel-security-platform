# Sentinel handoff

## Repository state

The repository began with only `test.md`. Phase 1 now includes a minimal Next.js 16 web application, project documentation, and a verified health endpoint. The work is on `v0/phase-1-foundation`; the existing commit history was preserved. No secrets were added. The existing `.env.development.local` was not read or modified.

## Files added

`package.json`, `package-lock.json`, `tsconfig.json`, `next-env.d.ts`, `next.config.ts`, `app/layout.tsx`, `app/page.tsx`, `app/globals.css`, `app/api/health/route.ts`, `README.md`, `ARCHITECTURE.md`, `API_CONTRACT.md`, `DECISIONS.md`, `PROJECT_STATUS.md`, `TESTING.md`.

## Implemented and verified result

Phase 1 remains intact, and Phase 2 backend foundation is now implemented in `backend/`: FastAPI routes, SQLAlchemy models, Alembic migration, Argon2 password hashing, JWT bearer auth, validation, and owner-scoped device/telemetry access. `pytest backend/test_api.py` passed with SQLite, the SQLite Alembic migration passed, `curl http://localhost:3000/api/health` returned the expected healthy web response, and the Next.js typecheck/build passed. PostgreSQL is configurable through `DATABASE_URL`, but persistence is explicitly unverified because no running PostgreSQL instance was available.

## Do not overwrite

Preserve the documentation contract and the distinction between planned services and verified services. Do not add fake data to make the dashboard appear complete.

## Phase 2 connection and verification

Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL and run `alembic upgrade head` from the project root. Then run the backend tests with that environment and add a PostgreSQL integration test run before declaring persistence verified. The local SQLite default exists only to make isolated API tests runnable without pretending PostgreSQL is connected.

## Phase 3 result

Added `backend/risk.py` as a deterministic, pure risk engine and `POST /api/v1/risk/assess` as an authenticated API boundary. The endpoint returns a capped 0–100 risk score, inverse security score, severity band, affected asset, evidence, timestamp, contribution, and recommended action for each recognized signal. Unknown signals are ignored and duplicate submissions are deduplicated.

The risk response is intentionally computed per request and is not presented as persisted database state. PostgreSQL remains configurable through `DATABASE_URL`; persistence and Alembic behavior must be verified against a running PostgreSQL instance before production claims. The current shell lacks `pytest`, so backend tests are not claimed as passing in this handoff.

## Next task

Install the pinned Python requirements, run `pytest backend/test_api.py`, then verify `alembic upgrade head` and the API against a running PostgreSQL database before adding persisted findings, anomaly detection, or simulator workflows.
