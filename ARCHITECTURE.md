# Sentinel architecture

## Current boundary

The web application owns navigation, accessible presentation, responsive layout, and status communication. It must never become the authoritative source for risk scores, authorization, telemetry truth, or ML output.

## Target boundaries

- `frontend/`: Next.js routes and reusable UI.
- `backend/`: FastAPI routes, Pydantic schemas, authorization, services, and tests.
- `backend/domain/`: deterministic risk engine, recommendations, simulation, and anomaly pipeline.
- `backend/infrastructure/`: PostgreSQL/SQLAlchemy, migrations, and Neo4j repository adapter.
- `ml/`: reproducible training and inference artifacts, with explicit synthetic-data labeling.
- `docs/`: supporting demonstrations and operational notes.

## Data flow

Authorized telemetry enters the FastAPI API, is validated and scoped to the authenticated user, persisted in PostgreSQL, evaluated by domain services, and exposed through versioned REST resources. Neo4j mirrors explicitly persisted or simulated relationships only when configured. The frontend consumes API results and renders their source and limitations.

## Phase 2 implementation

`backend/` is a separately runnable FastAPI service. SQLAlchemy models define users, devices, and telemetry events; Alembic contains the versioned initial migration. PostgreSQL is the deployment target through `DATABASE_URL`, while SQLite is used only for local smoke tests. JWT access tokens use Argon2 password hashes, and every device/telemetry query includes the authenticated user's owner boundary.

## Future service boundaries

Risk scoring is deterministic and independently testable. Isolation Forest training and inference share a stable feature schema. The graph adapter must degrade honestly when Neo4j is unavailable. Secrets are environment-only.
