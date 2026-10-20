# Architectural decisions

## 2026-10-21 — Start with a thin verified shell

The repository contained only `test.md`, so this phase establishes a minimal Next.js TypeScript application rather than attempting the full stack. Empty states are intentional: the project rules prohibit fabricated telemetry and scores.

## 2026-10-21 — Keep backend out of the web package for now

The target backend is Python/FastAPI, but no backend runtime or service configuration existed. It will be introduced in the database/auth phase with its own tests and environment contract.

## 2026-10-21 — Use semantic CSS tokens

The initial shell uses a small deep-navy/slate token set with restrained blue and status colors. This keeps the security product readable and avoids decorative effects before real data exists.
