# Architectural decisions

## 2026-10-21 — Start with a thin verified shell

The repository contained only `test.md`, so this phase establishes a minimal Next.js TypeScript application rather than attempting the full stack. Empty states are intentional: the project rules prohibit fabricated telemetry and scores.

## 2026-10-21 — Keep backend out of the web package

The Python/FastAPI service is separate from the Next.js web package. SQLAlchemy and Alembic own the persistence boundary, with PostgreSQL configured by `DATABASE_URL`; SQLite is limited to local tests until PostgreSQL verification is available.

## 2026-10-21 — Use semantic CSS tokens

The initial shell uses a small deep-navy/slate token set with restrained blue and status colors. This keeps the security product readable and avoids decorative effects before real data exists.
