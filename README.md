# PS 26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

AICTE Cyber Security Cell hackathon submission.

## Architecture
- **backend/** — FastAPI. Header forensics, content heuristics, a real
  scikit-learn Naive Bayes classifier trained at startup, a live SPF check
  via DNS-over-HTTPS, geolocation, and persisted case history
  (SQLite by default, Postgres via `DATABASE_URL`).
- **frontend/** — Next.js + Tailwind. The case-file/forensics-themed UI,
  calling the backend over a REST API.

## Quick start (local)
```bash
# Terminal 1 — backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```
Open http://localhost:3000, click **Load Sample Case**, then **Analyze Evidence**.

## Deployment
- Backend -> Render (see `backend/README.md`)
- Frontend -> Vercel (see `frontend/README.md`)
Point the frontend's `NEXT_PUBLIC_API_URL` at the deployed backend URL.

## What's genuinely real vs. simulated (be upfront about this with judges)
| Component | Status |
|---|---|
| Naive Bayes classifier | **Real** — scikit-learn `MultinomialNB`, trained at process startup on an embedded labeled corpus. Swap the corpus for a large real dataset to go from demo to production grade. |
| SPF check | **Real** — live, independent DNS-over-HTTPS TXT lookup against the actual origin IP, not just trusting a header. |
| DKIM / DMARC | Simulated — reads the `Authentication-Results` header only. Full DKIM needs RSA signature verification against the message body; not implemented. |
| GeoLocation | Real (free-tier `ipapi.co`) with a clearly-labeled offline fallback if unreachable. |
| Case history / cross-case matching | **Real** — persisted server-side in a database, shared across analysts, used to flag repeat sender domains/IPs across cases. |
| Attachment sandboxing, HTML MIME parsing at scale | Not implemented — noted as production roadmap. |
