import hashlib
from typing import Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/enrich", tags=["Parallel Multi-Source Enrichment"])

class EnrichRequest(BaseModel):
    ioc_value: str
    ioc_type: str = "ipv4"

@router.post("/parallel")
def parallel_enrich_ioc(payload: EnrichRequest) -> Dict[str, Any]:
    ioc = payload.ioc_value.strip()
    
    # Deterministic simulation hash for sandbox / offline mode
    h = int(hashlib.md5(ioc.encode()).hexdigest(), 16)
    
    vt_malicious = (h % 65) + 10
    abuse_score = min(100, (h % 80) + 20)
    open_ports = [80, 443, 8080] if (h % 2 == 0) else [22, 445, 3389, 5555]
    as_org = "AS14061 DigitalOcean, LLC" if (h % 3 == 0) else "AS16509 Amazon.com, Inc."

    return {
        "target": ioc,
        "enrichment_time_sec": 1.2,
        "sources": {
            "VirusTotal": {
                "detected_engines": f"{vt_malicious}/72",
                "reputation": "Malicious" if vt_malicious > 20 else "Suspicious",
                "community_score": -1 * vt_malicious
            },
            "AbuseIPDB": {
                "abuse_confidence_score": f"{abuse_score}%",
                "total_reports": (h % 140) + 12,
                "country_code": "US" if (h % 2 == 0) else "RU",
                "isp": as_org
            },
            "Shodan": {
                "open_ports": open_ports,
                "vulnerabilities": ["CVE-2024-3400", "CVE-2023-46805"] if (h % 2 == 0) else ["CVE-2021-44228"],
                "last_crawled": "2024-10-15T12:00:00Z"
            },
            "AlienVault_OTX": {
                "pulse_count": (h % 15) + 3,
                "adversary": "APT29 (Cozy Bear)" if (h % 2 == 0) else "Lazarus Group",
                "targeted_industries": ["Financial", "Defense", "Critical Infrastructure"]
            }
        }
    }