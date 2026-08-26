# Email Threat & Forensic Intelligence — Frontend (Next.js)

PS 26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Run locally
```
npm install
cp .env.local.example .env.local   # point NEXT_PUBLIC_API_URL at your backend
npm run dev
```
Open http://localhost:3000

## Deploy on Vercel
1. Push this `frontend/` folder to a GitHub repo.
2. On Vercel: New Project -> import the repo -> set Root Directory to `frontend`.
3. Add an environment variable: `NEXT_PUBLIC_API_URL` = your deployed backend URL
   (e.g. `https://your-app.onrender.com`).
4. Deploy. Vercel auto-detects Next.js — no extra config needed.
