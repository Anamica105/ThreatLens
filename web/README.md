# ThreatLens web

Next.js 15 (App Router) + Tailwind v4 frontend. See the repository README for setup.

- `npm run dev` — development server on :3000 (proxies `/api/*` to the API at `THREATLENS_API_URL`, default `http://127.0.0.1:8000`)
- `npm run build` — production build (`NEXT_OUTPUT=standalone` for Docker)
- Design tokens: `src/app/globals.css` (from design.md §29); components under `src/components`.
