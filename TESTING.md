# Testing record

## Commands

- `npm install` — passed; installed the initial web dependencies. npm reported advisories and a deprecation notice for the selected Next.js version; upgrade before production use.
- `npm run typecheck` — to be run after source creation.
- `npm run build` — to be run after source creation.
- `GET /api/health` — verified once the dev server is started.

No backend, database, graph, authentication, or ML tests exist yet. Do not interpret the current UI as evidence that those services work.
