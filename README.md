# Cyber Triage Tool

Lightweight cyber triage application with:
- React frontend (`web`) for case management, evidence upload, and triage results
- Express backend (`web/server.js`)
- In-memory SQLite database (`better-sqlite3`) for fast temporary analysis

## Features

- Create and select investigation cases
- Upload evidence files (`.txt`, `.log`, `.csv`, `.json`)
- Run triage analysis with IOC scoring
- Extract timestamped timeline events
- Generate live per-case report summary
- Handles bad inputs and edge cases with clear API errors

## Important Note

The database is in-memory only. Restarting the backend clears all cases and evidence.

## Run

```bash
cd web
npm install
npm run dev
```

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:5000`

## API Endpoints

- `GET /api/health`
- `GET /api/cases`
- `POST /api/cases`
- `GET /api/evidence?caseId=<id>`
- `POST /api/evidence` (multipart, fields: `caseId`, `file`)
- `POST /api/analyze`
- `GET /api/analyses?caseId=<id>`
- `GET /api/timeline?caseId=<id>`
- `GET /api/report/:caseId`# major-project
# major-project
