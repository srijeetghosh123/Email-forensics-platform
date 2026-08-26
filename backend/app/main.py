import uuid
import datetime
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_

from .classifier import classifier
from .forensics import analyze_email
from .external import check_spf, geolocate
from .db import init_db, get_db, Case

app = FastAPI(title="Email Threat & Forensic Intelligence API — PS 26106")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your deployed frontend origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


class AnalyzeRequest(BaseModel):
    raw_email: str


@app.get("/api/health")
def health():
    return {"status": "ok", "model": classifier.classify("test")["model"]}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)):
    raw = req.raw_email

    # 1. AI classifier pass (subject/body only — extracted inside forensics too,
    #    but the classifier needs the raw text directly)
    nb_result = classifier.classify(raw)

    # 2. Header forensics + content heuristics + relay chain
    result = analyze_email(raw, nb_result)

    # 3. Cross-case threat pattern matching against persisted case history
    threat_matches = []
    if result["from_domain"] or result["reply_domain"] or result["target_ip"]:
        filters = []
        if result["from_domain"]:
            filters.append(Case.from_domain == result["from_domain"])
        if result["reply_domain"]:
            filters.append(Case.reply_domain == result["reply_domain"])
        if result["target_ip"]:
            filters.append(Case.target_ip == result["target_ip"])
        prior_cases = db.query(Case).filter(or_(*filters)).order_by(Case.created_at.desc()).limit(10).all()
        for c in prior_cases:
            matched_on = (
                f"sender domain {result['from_domain']}" if c.from_domain == result["from_domain"] and result["from_domain"]
                else f"reply-to domain {result['reply_domain']}" if c.reply_domain == result["reply_domain"] and result["reply_domain"]
                else f"origin IP {result['target_ip']}"
            )
            threat_matches.append(
                f"Matches {matched_on} previously logged in case {c.case_id} ({c.verdict}, {c.created_at.isoformat()}) — possible repeat threat infrastructure."
            )
            result["score"] = min(100, result["score"] + 20)
            result["indicators"].append({"sev": "high", "text": threat_matches[-1]})

    # 4. Live SPF check (independent DNS-over-HTTPS lookup, not just the header)
    spf_result = None
    if result["from_domain"] and result["target_ip"]:
        spf_result = check_spf(result["from_domain"], result["target_ip"])
        if spf_result.get("found") is True and spf_result.get("mechanism_match") is False:
            result["score"] = min(100, result["score"] + 15)
            result["indicators"].append({"sev": "high", "text": f"Live SPF lookup: origin IP {result['target_ip']} is NOT listed in {result['from_domain']}'s published SPF record."})
        elif spf_result.get("found") is False:
            result["indicators"].append({"sev": "low", "text": f"Live SPF lookup: {result['from_domain']} publishes no SPF record."})
        elif spf_result.get("found") is True and spf_result.get("mechanism_match") is True:
            result["indicators"].append({"sev": "low", "text": f"Live SPF lookup: origin IP {result['target_ip']} matches an ip4 mechanism in {result['from_domain']}'s SPF record."})

    # 5. Geolocation
    geo = geolocate(result["target_ip"]) if result["target_ip"] else None

    # 6. Verdict
    score = result["score"]
    verdict = "PHISHING DETECTED" if score >= 65 else "SUSPICIOUS" if score >= 30 else "CLEAR"

    case_id = f"SIH26106-{uuid.uuid4().hex[:6].upper()}"
    response = {
        "case_id": case_id,
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "verdict": verdict,
        "score": score,
        "nb_classifier": nb_result,
        "headers": {
            "subject": result["subject"],
            "from": result["from"],
            "reply_to": result["reply_to"],
            "return_path": result["return_path"],
            "auth_results": result["auth_results"],
        },
        "indicators": result["indicators"],
        "relay_hops": result["relay_hops"],
        "target_ip": result["target_ip"],
        "spf_live": spf_result,
        "geolocation": geo,
        "threat_history_matches": threat_matches,
    }

    # 7. Persist case
    db_case = Case(
        case_id=case_id,
        subject=result["subject"],
        score=score,
        verdict=verdict,
        from_domain=result["from_domain"],
        reply_domain=result["reply_domain"],
        target_ip=result["target_ip"],
        full_result=response,
    )
    db.add(db_case)
    db.commit()

    return response


@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.created_at.desc()).limit(25).all()
    return [
        {
            "case_id": c.case_id,
            "created_at": c.created_at.isoformat(),
            "subject": c.subject,
            "score": c.score,
            "verdict": c.verdict,
        }
        for c in cases
    ]


@app.delete("/api/cases")
def clear_cases(db: Session = Depends(get_db)):
    db.query(Case).delete()
    db.commit()
    return {"status": "cleared"}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    c = db.query(Case).filter(Case.case_id == case_id).first()
    if not c:
        return {"error": "not found"}
    return c.full_result
