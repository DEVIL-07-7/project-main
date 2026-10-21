from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import SessionLocal, IoCRecord
from app.ml.engine import predict_single_ioc

router = APIRouter(prefix="/api/v1/org", tags=["Client Organization Custom Feeds"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class CustomLogBatch(BaseModel):
    organization_name: str
    log_type: str
    raw_logs: List[str]


@router.post("/ingest-feed")
def ingest_client_feed(payload: CustomLogBatch, db: Session = Depends(get_db)) -> Dict[str, Any]:
    processed_count = 0
    threats_discovered = []

    for line in payload.raw_logs:
        tokens = line.strip().split()
        for token in tokens:
            if "." in token and len(token) > 6:
                clean_target = token.strip(",;:\"'")
                scored = predict_single_ioc(clean_target, feed_confidence=70)

                if scored["risk_score"] >= 65:
                    existing = db.query(IoCRecord).filter(IoCRecord.ioc_value == clean_target).first()
                    if not existing:
                        rec = IoCRecord(
                            ioc_value=clean_target,
                            ioc_type="ipv4" if any(c.isdigit() for c in clean_target[:3]) else "domain",
                            threat_type="org_internal_telemetry",
                            tags=[f"org:{payload.organization_name}", payload.log_type],
                            source_feeds=[f"ClientOrg-{payload.organization_name}"],
                            feed_confidence=70,
                            risk_score=scored["risk_score"],
                        )
                        db.add(rec)
                        threats_discovered.append(clean_target)
                processed_count += 1

    db.commit()
    return {
        "status": "success",
        "organization": payload.organization_name,
        "indicators_parsed": processed_count,
        "critical_threats_isolated": len(threats_discovered),
        "flagged_iocs": threats_discovered,
    }


@router.get("/graph-correlations")
def get_graph_correlations(db: Session = Depends(get_db)) -> Dict[str, Any]:
    records = db.query(IoCRecord).order_by(IoCRecord.risk_score.desc()).limit(12).all()

    nodes = [
        {"id": "Campaign: DarkHydra", "group": "campaign", "val": 25},
        {"id": "Actor: APT29", "group": "actor", "val": 20},
        {"id": "Actor: Lazarus Group", "group": "actor", "val": 20},
    ]
    links = [{"source": "Actor: APT29", "target": "Campaign: DarkHydra"}]

    for r in records:
        nodes.append({"id": r.ioc_value, "group": "ioc", "val": 10})
        target_group = "Campaign: DarkHydra" if r.id % 2 == 0 else "Actor: Lazarus Group"
        links.append({"source": target_group, "target": r.ioc_value})

        for t in (r.tags or [])[:2]:
            tag_id = f"TTP: {t}"
            if not any(n["id"] == tag_id for n in nodes):
                nodes.append({"id": tag_id, "group": "tag", "val": 6})
            links.append({"source": r.ioc_value, "target": tag_id})

    return {"nodes": nodes, "links": links}