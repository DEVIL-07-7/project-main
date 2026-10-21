from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional, Dict, Any

from app.database import SessionLocal, IoCRecord
from app.ml.engine import predict_single_ioc, train_and_save_models
from app.ml.nlp_extractor import extract_threat_intel_from_text
from app.ingest import run_ingestion_pipeline

router = APIRouter(prefix="/api/v1", tags=["Sentinel-TIP Intelligence API"])


# Dependency to get DB session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Request Payloads ---
class ScanIoCRequest(BaseModel):
    ioc_value: str = Field(..., min_length=3, description="URL, Domain, or IPv4 to analyze")


class ReportExtractRequest(BaseModel):
    text: str = Field(..., min_length=10, description="Unstructured security blog, advisory, or incident log")


# --- 1. Dashboard Overview & Telemetry Stats ---
@router.get("/stats")
def get_platform_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    total_iocs = db.query(IoCRecord).count()
    critical_count = db.query(IoCRecord).filter(IoCRecord.risk_score >= 70).count()
    anomaly_count = db.query(IoCRecord).filter(IoCRecord.is_anomaly == 1).count()
    avg_risk = db.query(func.avg(IoCRecord.risk_score)).scalar() or 0.0

    # Group by IoC Type (url, ipv4, domain, sha256)
    type_rows = (
        db.query(IoCRecord.ioc_type, func.count(IoCRecord.id))
        .group_by(IoCRecord.ioc_type)
        .all()
    )
    by_type = [{"name": t.upper(), "value": c} for t, c in type_rows]

    # Group by Threat Type (malware_download, botnet_c2, etc.)
    threat_rows = (
        db.query(IoCRecord.threat_type, func.count(IoCRecord.id))
        .group_by(IoCRecord.threat_type)
        .all()
    )
    by_threat = [{"name": t, "count": c} for t, c in threat_rows]

    return {
        "total_iocs": total_iocs,
        "critical_threats": critical_count,
        "anomalies_flagged": anomaly_count,
        "average_risk_score": round(float(avg_risk), 1),
        "ioc_type_distribution": by_type,
        "threat_type_distribution": by_threat,
    }


# --- 2. List & Filter Database Indicators ---
@router.get("/iocs")
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by url, ipv4, or domain"),
    search: Optional[str] = Query(None, description="Search substring in IoC value"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    query = db.query(IoCRecord)

    if ioc_type and ioc_type != "all":
        query = query.filter(IoCRecord.ioc_type == ioc_type.lower())
    if search:
        query = query.filter(IoCRecord.ioc_value.ilike(f"%{search.strip()}%"))

    records = query.order_by(IoCRecord.risk_score.desc(), IoCRecord.last_seen.desc()).limit(limit).all()

    return [
        {
            "id": r.id,
            "ioc_value": r.ioc_value,
            "ioc_type": r.ioc_type,
            "threat_type": r.threat_type,
            "tags": r.tags or [],
            "source_feeds": r.source_feeds or [],
            "status": r.status,
            "sighting_count": r.sighting_count,
            "feed_confidence": r.feed_confidence,
            "ml_malicious_prob": r.ml_malicious_prob,
            "is_anomaly": bool(r.is_anomaly),
            "risk_score": r.risk_score,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in records
    ]


# --- 3. Real-Time On-Demand ML IoC Scanner ---
@router.post("/scan/ioc")
def scan_ioc_endpoint(payload: ScanIoCRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    target = payload.ioc_value.strip()

    # Check if this indicator is already known in our threat database
    existing = db.query(IoCRecord).filter(IoCRecord.ioc_value == target).first()
    feed_conf = existing.feed_confidence if existing else 50

    prediction = predict_single_ioc(target, feed_confidence=feed_conf)

    if existing:
        prediction["known_in_db"] = True
        prediction["source_feeds"] = existing.source_feeds
        prediction["tags"] = existing.tags
        prediction["threat_type"] = existing.threat_type
        prediction["reasons"].insert(
            0, f"Corroborated by known OSINT feed(s): {', '.join(existing.source_feeds or [])}"
        )
    else:
        prediction["known_in_db"] = False
        prediction["source_feeds"] = []
        prediction["tags"] = []
        prediction["threat_type"] = "unclassified_live_scan"

    return prediction


# --- 4. Unstructured Threat Advisory NLP & MITRE Extractor ---
@router.post("/extract/report")
def analyze_threat_report(payload: ReportExtractRequest) -> Dict[str, Any]:
    extraction = extract_threat_intel_from_text(payload.text)

    # Automatically score extracted URLs, IPs, and Domains using our ML engine
    scored_indicators = []
    candidates = (
        extraction["extracted_iocs"]["urls"]
        + extraction["extracted_iocs"]["ipv4s"]
        + extraction["extracted_iocs"]["domains"]
    )

    for ind in candidates[:15]:
        verdict_data = predict_single_ioc(ind, feed_confidence=65)
        scored_indicators.append({
            "ioc_value": ind,
            "verdict": verdict_data["verdict"],
            "risk_score": verdict_data["risk_score"],
            "ml_malicious_probability": verdict_data["ml_malicious_probability"],
            "is_anomaly": verdict_data["is_anomaly"],
        })

    extraction["ml_scored_indicators"] = scored_indicators
    return extraction


# --- 5. Trigger Live Feed Ingestion & Re-Scoring ---
@router.post("/feeds/refresh")
def trigger_feed_refresh() -> Dict[str, Any]:
    try:
        run_ingestion_pipeline(limit_per_feed=25)
        metrics = train_and_save_models()
        return {
            "status": "success",
            "message": "Live OSINT feeds ingested and ML risk scores updated.",
            "model_metrics": metrics,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/graph/correlation")
def get_correlation_graph(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Simulates a Neo4j Graph Correlation extraction for the frontend visualizer.
    In production, this would use the neo4j python driver to query connected subgraphs.
    """
    # Fetch top critical IOCs
    critical_iocs = db.query(IoCRecord).filter(IoCRecord.risk_score >= 80).limit(5).all()
    
    nodes = [{"id": "Threat Actor: APT29", "group": 1, "val": 20}]
    links = []
    
    for ioc in critical_iocs:
        nodes.append({"id": ioc.ioc_value, "group": 2, "val": 10})
        links.append({"source": "Threat Actor: APT29", "target": ioc.ioc_value})
        
        # Correlate tags
        for tag in ioc.tags[:2]:
            if not any(n["id"] == tag for n in nodes):
                nodes.append({"id": tag, "group": 3, "val": 5})
            links.append({"source": ioc.ioc_value, "target": tag})
            
    return {"nodes": nodes, "links": links}