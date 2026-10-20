# Testing record

## Commands

- `npm install` — passed; installed the initial web dependencies. npm reported advisories and a deprecation notice for the selected Next.js version; upgrade before production use.
- `npm run typecheck` — passed.
- `npm run build` — passed with Next.js 16 production output.
- `GET /api/health` — passed; returned `status: ok`, `web: ok`, `database: not_configured`, and `graph: not_configured`.

No backend, database, graph, authentication, or ML tests exist yet. Do not interpret the current UI as evidence that those services work.
