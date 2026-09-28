# ThreatLens

ThreatLens is an internal, agent-driven research workbench. A threat hunter pastes a threat (a headline, CVE, actor, campaign or article URL) and picks a client workspace. The pipeline then:

1. collects sources from allow-listed vendor feeds (and the open web, if configured),
2. reads each article,
3. synthesises one research record where every claim traces back to its source,
4. maps the behaviours to MITRE ATT&CK,
5. writes Sigma rules and translates them into each client's query language,
6. enriches the IoCs against OSINT services,
7. publishes a report that exports as PDF, email HTML, a 2-slide PPTX, JSON or CSV.

Every run also feeds the shared libraries of threat actors, malware and tools, queries, and IoCs.

It is built from `ThreatLens — MVP Product Design Spec` and `design.md` (design system v1.1).

```
api/   FastAPI + SQLAlchemy backend, pipeline agents, exports   (Python 3.12)
web/   Next.js 15 + Tailwind v4 frontend                         (Node 20+)
```

## Quick start (Windows)

```bash
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

On first run the script creates `api/.venv`, installs the Python and Node dependencies and the headless Chromium (used for PDF export and for JavaScript-rendered articles), and copies `api/.env.example` to `api/.env`. It then starts the API on :8000 and the web app on :3000. Open http://localhost:3000.

The database is seeded with:
- three client workspaces: Acme Bank, Northwind Health and Contoso Energy
- four users with different roles
- the **ToolShell dry-run record** from spec §4 (`TR-2026-0142`)
- a few sample records for the dashboards

Switch user (hunter / reviewer / lead) from the account menu at the bottom of the sidebar. Publishing requires reviewer, lead or admin.

To run each service yourself:

```bash
cd api; .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```
```bash
cd web; npm run dev
```

### Docker / PostgreSQL

```bash
docker compose up --build
```

This runs PostgreSQL 16, the API and a standalone Next.js build. For a local PostgreSQL without Docker, set `DATABASE_URL=postgresql+psycopg://…` in `api/.env` and `pip install "psycopg[binary]"`.

## Configuration (`api/.env`)

| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | Enables the LLM agents (Claude, `LLM_MODEL`, default `claude-opus-5`) for intake, per-article extraction, synthesis, ATT&CK mapping, detection reasoning and query writing. **Without it the pipeline runs in offline mode** (regex, keyword heuristics and canned detection templates). Offline mode works end to end but produces much weaker narrative text. |
| `BRAVE_SEARCH_API_KEY` | Open-web source discovery. Without it, discovery uses seed URLs plus the vendor RSS feeds. |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `ABUSECH_AUTH_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY` | OSINT enrichment. You can also set these in **Settings → OSINT API keys**. |
| `DATABASE_URL` | SQLite by default (`api/threatlens.db`). |
| `WEB_BASE_URL` | Used for the "Read the full report" links in exports. |

LLM calls use structured outputs. They also enable the API's server-side refusal fallback (`fallbacks: "default"`), because threat research can trip the cyber safety classifier on the primary model. Fetched article text is always passed to the model as untrusted data, and the model is told not to follow instructions found in it.

## Where the spec lives in the code

| Spec | Implementation |
|---|---|
| §2 pipeline (10 stages, per-stage retry, IoC enrichment in parallel) | `api/app/pipeline/runner.py`, `stages.py` |
| §4 dry run | `api/app/seed.py` |
| §5 schema v1 | `api/app/pipeline/schemas.py`, record assembled in `stage_report` |
| §6 IA, workspace switcher (`?ws=`), command palette | `web/src/components/shell/*`, `providers.tsx` |
| §7 pages | `web/src/app/**` |
| §8 detection engineering (Sigma → 9 platforms, log sources, lint, field mappings, coverage gaps) | `api/app/detection.py`, `web/src/components/research/query-block.tsx` |
| §9 IoC extraction, refang/defang, allow-lists, OSINT, verdict logic | `api/app/ioc.py`, `api/app/osint.py` |
| §10 exports (PDF, email/.eml, 2-slide PPTX, JSON, CSV, period XLSX + summary PDF) | `api/app/exports/*` |
| §11 data model | `api/app/models.py` |
| §12 source discovery / fetching (httpx + trafilatura + Playwright), guardrails | `api/app/sources.py`, `api/app/llm.py` |
| design.md tokens, components, tree view, tactic rail | `web/src/app/globals.css`, `web/src/components/**` |

## Tests

```bash
cd api; .\.venv\Scripts\python.exe -m pytest tests -q
```

The smoke tests cover the seed data, the library and search APIs, detection translation and lint for every platform, IoC refang/defang, all exports, the review workflow, a full offline pipeline run, and re-running a single stage.

## Notes and deliberate simplifications

- **Auth.** The spec calls for SSO (OIDC). This build sends the signed-in user in an `X-User` header chosen from the account menu. In production, put an OIDC proxy in front of the API and map its identity header in `api/app/deps.py`.
- **Job queue.** Stages run in an in-process thread pool (`runner.py`). For multi-node deployments, swap it for Celery or Arq on Redis. `execute_run(run_id, from_stage)` is the task entry point. A run interrupted by an API restart is marked failed and can be resumed with **Retry stage**.
- **OSINT keys** entered in Settings are stored in the database. Use environment variables or a vault in production.
- **ATT&CK catalog.** A bundled subset ships with the app. **Settings → System → Sync now** downloads the full current Enterprise matrix from MITRE.
- **ToolShell seed record.** The indicators are the publicly reported ones. The evidence quotes are paraphrased, and OSINT reputation is left empty until keys are added. Verify against the linked articles before any client use.
- **Colour palette.** design.md is the source of truth. The dataviz palette validator flags teal `#2F8580` as low-chroma, and flags Critical vs High severity as close under normal vision. Every chart therefore labels categories directly and never relies on colour alone.
- **P1/P2 items** (email intake, STIX/MISP, lab validation, watchlists) are not built. Re-run and version diff, comments, hunt-result logging, and actor, malware, query and IoC profile editing are included.
