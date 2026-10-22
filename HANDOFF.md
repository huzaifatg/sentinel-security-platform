# Sentinel handoff

## Repository state

The repository began with only `test.md`. Phase 1 now includes a minimal Next.js 16 web application, project documentation, and a verified health endpoint. The work is on `v0/phase-1-foundation`; the existing commit history was preserved. No secrets were added. The existing `.env.development.local` was not read or modified.

## Files added

`package.json`, `package-lock.json`, `tsconfig.json`, `next-env.d.ts`, `next.config.ts`, `app/layout.tsx`, `app/page.tsx`, `app/globals.css`, `app/api/health/route.ts`, `README.md`, `ARCHITECTURE.md`, `API_CONTRACT.md`, `DECISIONS.md`, `PROJECT_STATUS.md`, `TESTING.md`.

## Implemented and verified result

Phase 1 remains intact, and Phase 2 backend foundation is now implemented in `backend/`: FastAPI routes, SQLAlchemy models, Alembic migration, Argon2 password hashing, JWT bearer auth, validation, and owner-scoped device/telemetry access. `uv run --with-requirements requirements.txt -- python -m pytest backend/test_api.py -q` passed with 6 SQLite-backed tests, including authentication, risk boundaries/caps/evidence, ownership enforcement, validation, and telemetry. The live dashboard opened and rendered, `http://localhost:3000/api/health` returned the expected healthy web response, and the Next.js typecheck/build passed with Next.js 16.4.2. PostgreSQL is configurable through `DATABASE_URL`, but persistence is explicitly unverified because no running PostgreSQL instance was available.

## Do not overwrite

Preserve the documentation contract and the distinction between planned services and verified services. Do not add fake data to make the dashboard appear complete.

## Phase 2 connection and verification

Set `DATABASE_URL` to a PostgreSQL SQLAlchemy URL and run `alembic upgrade head` from the project root. Then run the backend tests with that environment and add a PostgreSQL integration test run before declaring persistence verified. The local SQLite default exists only to make isolated API tests runnable without pretending PostgreSQL is connected.

## Phase 3 result

Added `backend/risk.py` as a deterministic, pure risk engine and `POST /api/v1/risk/assess` as an authenticated API boundary. The endpoint returns a capped 0–100 risk score, inverse security score, severity band, affected asset, evidence, timestamp, contribution, and recommended action for each recognized signal. Unknown signals are ignored and duplicate submissions are deduplicated.

The risk response is intentionally computed per request and is not presented as persisted database state. PostgreSQL remains configurable through `DATABASE_URL`; persistence and Alembic behavior must be verified against a running PostgreSQL instance before production claims. Backend verification now passes via the isolated `uv run --with-requirements requirements.txt` environment: 6 tests are green. The tests use SQLite and do not prove PostgreSQL persistence.

## Phase 4 result

Added authenticated, owner-scoped anomaly routes (`/api/v1/anomalies/model/train`, `/api/v1/anomalies/detect`, and `/api/v1/anomalies`) using a persisted scikit-learn Isolation Forest artifact and persisted evidence-backed event records. Added authenticated simulator create/list routes with scenario validation and persisted baseline/modified risk outputs. Models and Alembic migration `0002_phase4` are included. Focused tests now cover anomaly training/inference, evidence serialization, simulator determinism/non-mutation, and cross-user ownership; the full SQLite API suite passes with 9 tests. A response serialization defect found by those tests was fixed so JSON feature and finding fields are returned as typed arrays/objects rather than database strings. PostgreSQL persistence and model artifact durability remain unverified until a running PostgreSQL environment is configured.

## Verification checkpoint

The live preview opens and the main dashboard renders at the current desktop viewport (1078x813, dark mode). `GET /api/health` returns `status: ok` with `web: ok`, `database: not_configured`, and `graph: not_configured`. The 9-test SQLite API suite, SQLite Alembic upgrade, frontend typecheck, lint, and production build pass. The dashboard risk-assessment form is wired to the FastAPI response path and explicitly shows an unavailable state rather than fabricating scores or findings when no authenticated backend response is available. The earlier deployment blocker was the vulnerable `next@16.0.0`; the dependency is now `next@16.4.2`, but no new production deployment has been run in this checkpoint.

## Render and Neon preparation

The backend entry point is `backend.main:app`, started with `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`. A Render backend Web Service should deploy branch `v0/phase-1-foundation` (the historical `main` commit used by the failed deployment lacks `requirements.txt` and `backend/`), use the repository root, build with `pip install -r requirements.txt`, and configure server-side `DATABASE_URL`, `JWT_SECRET`, `JWT_ALGORITHM`, `ACCESS_TOKEN_MINUTES`, and `CORS_ORIGINS`. Python is pinned with `.python-version` to `3.13.11` for the pinned dependency set. The frontend should use `NEXT_PUBLIC_API_URL` for the public backend origin; no database credentials belong in frontend variables.

`DATABASE_URL` accepts Neon's pooled `postgresql://...` URL and normalizes it to `postgresql+psycopg://...` because `psycopg[binary]` is installed. `alembic upgrade head` runs from the repository root and reads the same environment as the service. This preparation has not connected to Neon, run migrations, or verified PostgreSQL CRUD.

## Frontend completion checkpoint

The frontend now includes a complete navigable Sentinel workspace across overview, devices, risk findings, digital twin, anomalies, simulator, activity, reports, and settings. It preserves the dark operational dashboard language and clearly labels demo-only data. The risk console continues to call the existing FastAPI risk endpoint and presents an unavailable state when no authenticated backend response is available; it does not fabricate live findings.

The live preview was verified at 1137x813 in dark mode: overview and `/devices` rendered successfully. `npm run typecheck`, `npm run lint`, and `npm run build` all pass. Route coverage is provided by the root page plus the shared catch-all route; no authentication or database claims were added.

## Deployment migration check

Added `render-build.sh` as the explicit Render build command. It changes to the repository root, installs `requirements.txt`, prints migration start/success markers, and runs `python -m alembic upgrade head`; `set -euo pipefail` makes migration failures fail the build without logging connection strings. The health endpoint now performs `SELECT 1` and checks `alembic_version`, reporting `configured`, `connectivity`, and `schema` separately. This improves observability but does not verify the deployed database until Render runs the build against its configured `DATABASE_URL`.

## Next task

Configure a running PostgreSQL test environment and verify `alembic upgrade head`, persistence, and authentication against it. Do not claim production persistence or a successful production deployment until those checks and a deployment run pass.
