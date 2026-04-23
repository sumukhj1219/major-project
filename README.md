# Cyber Triage Tool

A lightweight SOC-style log triage app for fast case analysis.

- Frontend: React + Vite (`web/src/App.jsx`)
- Backend: Express (`web/server.js`)
- Data store: in-memory SQLite (`node:sqlite`)

## What It Does

- Manage investigation cases (create/select/delete)
- Upload evidence files (`.txt`, `.log`, `.csv`, `.json`)
- Normalize logs into a common event format
- Detect likely provider/source (Supabase, Neon, Postgres, AWS, etc.)
- Run IOC-based analysis with threat scoring
- Build timeline events from parsed timestamps
- Generate case report with top findings and recommendations
- Show analyst-focused dashboards and charts
- Optional live URL enrichment via Playwright:
  - analyze suspicious URLs extracted from evidence
  - manually enrich user-provided URLs
  - return status, redirect target, title, snippet, and auth-wall hint

## Current Limitations

- Database is in-memory only. Restarting backend clears all cases and evidence.
- Dashboard URLs (for example Supabase/AWS consoles) are usually auth-protected, so URL enrichment may return login/redirect previews instead of private content.

## Local Setup

```bash
cd web
npm install
npx playwright install chromium
npm run dev
```

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:5000`

## API Endpoints

- `GET /api/health`
- `GET /api/cases`
- `POST /api/cases`
- `DELETE /api/cases/:caseId`
- `GET /api/evidence?caseId=<id>`
- `POST /api/evidence` (multipart: `caseId`, `file`)
- `DELETE /api/evidence/:evidenceId`
- `POST /api/analyze` (`evidenceId`, optional `enrichWithPlaywright`)
- `POST /api/analyze-case` (`caseId`, optional `enrichWithPlaywright`)
- `GET /api/analyses?caseId=<id>`
- `GET /api/timeline?caseId=<id>&q=<keyword>`
- `GET /api/report/:caseId`
- `POST /api/enrich-url` (`url`)

## Claude PRD Prompt (Copy/Paste)

Use this prompt in Claude to generate a high-quality PRD for this project:

```text
You are a senior product manager and security product writer.

Create a professional Product Requirements Document (PRD) for this project:
"Cyber Triage Tool" - a web app for SOC analysts to triage logs quickly.

Product context:
- React frontend + Express backend + in-memory SQLite.
- Users can create cases, upload evidence logs (.txt/.log/.csv/.json), run IOC analysis, and review timeline + report views.
- Log normalization supports mixed formats (text/CSV/JSON) and provider hints (Supabase, Neon, Postgres, etc.).
- Analysis outputs include line count, IOC count, threat score, risk level, and summary.
- Timeline events are extracted from parsed timestamps.
- URL enrichment is optional using Playwright:
  - auto-enrichment of suspicious URLs found in evidence
  - manual URL enrichment input
  - metadata: status, final URL, redirects, title, content type, snippet, auth-wall detection.
- Reports include executive brief, top findings, and recommendations.

Key UX goals:
- concise but informative analyst outputs
- clear risk prioritization
- evidence-backed findings (log previews, context cards)
- low-friction triage workflow

Known constraints:
- data is ephemeral (in-memory DB)
- auth-gated dashboard URLs may not expose private content through enrichment

Write PRD sections:
1) Problem Statement
2) Goals and Non-Goals
3) Target Users and Personas
4) User Stories / Jobs To Be Done
5) Functional Requirements (MVP vs Next)
6) Non-Functional Requirements (performance, reliability, security)
7) Data Model and API Requirements
8) UX Requirements and Information Architecture
9) Metrics / Success Criteria
10) Risks, Assumptions, and Open Questions
11) Rollout Plan and Milestones
12) Future Enhancements

Include:
- clear acceptance criteria per major feature
- prioritized backlog table (P0/P1/P2)
- one-page executive summary at top
- concise writing, no fluff
```
