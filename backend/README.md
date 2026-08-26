# Email Threat & Forensic Intelligence — Backend (FastAPI)

PS 26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Run locally
```
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API docs: http://localhost:8000/docs

## Endpoints
- `POST /api/analyze` — body `{"raw_email": "<full raw email source>"}`, returns full analysis
- `GET /api/cases` — list persisted case history
- `DELETE /api/cases` — clear case history
- `GET /api/cases/{case_id}` — fetch one stored case
- `GET /api/health` — health check

## Deploy on Render
1. Push this `backend/` folder to a GitHub repo (or a subfolder of your monorepo).
2. On Render: New -> Web Service -> connect the repo.
   - Root directory: `backend`
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
3. (Optional) Add a Render Postgres instance and set `DATABASE_URL` env var —
   the app switches from SQLite to Postgres automatically, no code changes.
4. Copy the deployed URL (e.g. `https://your-app.onrender.com`) into the
   frontend's `NEXT_PUBLIC_API_URL`.

## Notes on what's real vs. simulated
- Naive Bayes classifier: genuinely trained (scikit-learn `MultinomialNB`)
  at process startup on the small embedded corpus in `app/classifier.py`.
  Swap in a larger real labeled dataset to move from demo to production grade.
- SPF: live, independent DNS-over-HTTPS check against the actual origin IP —
  not just trusting the `Authentication-Results` header.
- DKIM/DMARC: read from the `Authentication-Results` header only. Full DKIM
  needs RSA signature verification against the message body and the DKIM
  public key fetched from DNS — not implemented here.
- GeoLocation: free-tier `ipapi.co`; falls back to a clearly-labeled offline
  reference dataset if unreachable.
