# Sentinel — Continuous Cyber Risk & Financial Exposure

AI-powered platform that scans your code like a friendly hacker, converts every bug into rupees of risk, and tells you exactly what to fix first and what it pays back.

Paste a GitHub link, upload a ZIP, or pick a code folder directly. The app copies it into a locked practice area, runs safe attacks there, and shows danger scores, money at risk, fix plans, and compliance — your live app is never touched.

## What it does

**Three ways to scan**
- GitHub link — shallow-clones public repos (private repos work with a one-time access token that is never stored) into an isolated copy and scans it.
- ZIP upload — extracts archives and scans the contents.
- Folder upload — pick a codebase folder straight from disk, no zipping needed.

**Safe hacking simulation**
- Primary engine is an AI pentest team in a Docker sandbox: recon, exploitation, and result chaining, all against the copied code only, with proof for every finding.
- Without Docker or AI keys it falls back to a built-in static analyzer covering injection, broken access, secrets, server-side and client-side flaws.

**Money math, not just severities**
- Danger score per bug (0–100) from severity, exploitability, exposure, asset importance, threat activity, and protection in place.
- Safety score per project from danger scores weighted by severity.
- Money at risk per bug and total yearly expected loss from asset value, breach size, downtime, fines, and brand damage times likelihood. Worst-case bill from thousands of simulated years.

**AI agents**
- Risk advisor answering plain-English questions, fix planner with savings percent and cost, trend forecaster, document assistant with cited sources, and an attack defender that blocks hidden poison instructions in retrieved docs.

**Investment optimizer**
- Fix catalog with cost and savings, knapsack optimization for maximum risk reduction inside your budget, return-on-security-investment, and a curve showing where extra spending stops paying.

**Compliance mapping**
- Every finding auto-tagged to ISO 27001, NIST framework, CIS controls, RBI, and SEBI with pass-fail per control and an overall governance score.

**Dashboards**
- Check-a-project flow, executive overview (safety, money at risk, fix-today count, fix time, proved-by-testing), problems-found table with file, danger, loss and fix cost, fix planner, what-if simulator, and a RAG attack lab demo.

## Tech stack

- Frontend: React single-page app with charts and PDF export.
- Backend: Python API server. Risk math with numerical libraries, vector search for documents.
- AI: NVIDIA cloud API — large reasoning model for answers and plans, small safety model plus filters for defense, cloud embeddings with local fallback.
- Scanning and infra: AI pentest engine in Docker, Git for cloning, local disk for practice copies and reports.

## Quick start

```powershell
Set-Location "D:\hackathon\cyber-risk-platform"
Copy-Item .env.example .env   # then paste your NVIDIA_API_KEY into .env
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open `http://127.0.0.1:8001/` (port 8000 is often taken by Docker Desktop — use 8001).
Legacy dashboard remains at `/legacy`.

## Configuration

Only one secret is needed. Copy `.env.example` to `.env` and set:

```
NVIDIA_API_KEY=your_key_from_build.nvidia.com
```

Endpoint and model ship pre-filled. Never commit `.env` — it is git-ignored.

## Key API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/sentinel/scan-git` | Clone GitHub link + scan (`repo_url`, optional `access_token`) |
| POST | `/api/sentinel/upload` | ZIP upload + scan |
| POST | `/api/sentinel/upload-folder` | Raw folder upload + scan |
| GET | `/api/sentinel/latest` | Latest project + findings (empty until first scan) |
| GET | `/api/risk/summary` | Expected loss, worst-case, scores |
| POST | `/api/query` | Plain-English risk question |
| POST | `/api/simulate` | What-if (MFA, patching, delays) |
| GET | `/api/investment/optimize?budget=10000000` | Best fixes for budget |
| GET | `/api/compliance/{framework}` | ISO27001, NIST, CIS, RBI, SEBI |
| POST | `/api/rag/query` | Document-grounded answer |
| POST | `/api/attack/rag-poison` | Poisoned-vs-guarded demo |
| POST | `/api/clear` | Reset all results |

## Notes

- Results appear only after a real scan of your codebase — no demo data is shipped.
- Authorized use only: scan code you own or have written permission to test.
