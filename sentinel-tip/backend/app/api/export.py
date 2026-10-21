from datetime import datetime
from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import SessionLocal, IoCRecord

router = APIRouter(prefix="/api/v1/export", tags=["SIEM/SOAR/EDR Integrations"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/{platform}")
def export_iocs_for_siem(platform: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    critical_records = db.query(IoCRecord).filter(IoCRecord.risk_score >= 70).limit(50).all()
    ioc_list = [r.ioc_value for r in critical_records]

    if platform.lower() == "splunk":
        spl = "index=* (" + " OR ".join([f'dest="{ioc}" OR query="{ioc}"' for ioc in ioc_list[:15]]) + ")"
        return {"platform": "Splunk", "format": "SPL", "export_query": spl}

    elif platform.lower() == "sentinel":
        kql = "CommonSecurityLog | where DestinationIP in (" + ", ".join([f'"{ioc}"' for ioc in ioc_list[:20]]) + ")"
        return {"platform": "Microsoft Sentinel", "format": "KQL", "export_query": kql}

    elif platform.lower() == "qradar":
        aql = "SELECT * FROM events WHERE " + " OR ".join([f'INCIDENT_IP = "{ioc}"' for ioc in ioc_list[:15]])
        return {"platform": "IBM QRadar", "format": "AQL", "export_query": aql}

    elif platform.lower() == "crowdstrike":
        csv_lines = ["type,value,action,severity,description"]
        for r in critical_records:
            t = "ipv4" if r.ioc_type == "ipv4" else "domain"
            csv_lines.append(f"{t},{r.ioc_value},prevent,critical,ThreatOps Automated Block")
        return {"platform": "CrowdStrike Falcon", "format": "CSV", "payload": "\n".join(csv_lines)}

    elif platform.lower() == "stix":
        bundle = {
            "type": "bundle",
            "id": f"bundle--threatops-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{r.id}",
                    "name": f"Malicious {r.ioc_type}",
                    "pattern": f"[{r.ioc_type}:value = '{r.ioc_value}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                    "confidence": int(r.risk_score),
                }
                for r in critical_records
            ],
        }
        return {"platform": "STIX/TAXII 2.1", "format": "JSON", "payload": bundle}

    return {"error": f"Platform '{platform}' not supported"}