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

## Deploy the FastAPI backend on Render with Neon

The backend is intended to run as a separate Render Web Service from this repository root. The Next.js app remains the frontend; Render is not used to host the backend inside the Next.js process.

1. In Render, create a **Web Service** connected to this repository and use the repository root (`/`) as the service root.
2. Use `pip install -r requirements.txt` as the build command.
3. Use `uvicorn backend.main:app --host 0.0.0.0 --port $PORT` as the start command.
4. Add these Render environment variables under the backend service: `DATABASE_URL`, `JWT_SECRET`, `JWT_ALGORITHM`, `ACCESS_TOKEN_MINUTES`, and `CORS_ORIGINS`. Set `CORS_ORIGINS` to the deployed Next.js origin, not a browser-facing secret.
5. Run the first migration from the repository root in a shell using the same environment: `alembic upgrade head`. This is non-destructive for a new database and must complete before claiming PostgreSQL persistence is verified.
6. Set the frontend deployment's `NEXT_PUBLIC_API_URL` to the public Render backend URL, for example `https://sentinel-api.onrender.com`. The current dashboard intentionally remains safe when this variable is absent; it does not fabricate backend results.

`DATABASE_URL` may be Neon's pooled `postgresql://...` URL with `sslmode=require`; the backend normalizes that scheme to `postgresql+psycopg://...` for the installed Psycopg 3 driver. Do not commit `.env` files or paste credentials into source control. The health endpoint reports configuration status only; verify a real connection with `alembic upgrade head`, authenticated CRUD, and `GET /api/v1/health` against the deployed service before treating the database as connected.

## Limitations

The current dashboard deliberately uses empty states rather than fabricated scores, devices, alerts, or telemetry. Any future collection must be explicitly authorized and identify whether data is collected or simulated.
