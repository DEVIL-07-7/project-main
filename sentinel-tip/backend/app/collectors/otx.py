import os
import requests
from datetime import datetime
from typing import List
from dotenv import load_dotenv
from app.schemas import NormalizedIoC

load_dotenv()

OTX_PULSES_ENDPOINT = "https://otx.alienvault.com/api/v1/pulses/subscribed"

TYPE_MAPPING = {
    "IPv4": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-SHA256": "sha256",
}

def fetch_otx_indicators(limit: int = 25) -> List[NormalizedIoC]:
    """
    Fetches indicators from AlienVault OTX subscribed pulses if OTX_API_KEY is configured.
    """
    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        print("[!] OTX_API_KEY not found in .env — skipping AlienVault OTX collector.")
        return []

    print("[*] Fetching threat pulses from AlienVault OTX...")
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(OTX_PULSES_ENDPOINT, headers=headers, params={"limit": 5}, timeout=30)
    response.raise_for_status()

    pulses = response.json().get("results", [])
    normalized_iocs: List[NormalizedIoC] = []

    for pulse in pulses:
        pulse_tags = pulse.get("tags", [])[:5]
        for ind in pulse.get("indicators", []):
            raw_type = ind.get("type")
            if raw_type not in TYPE_MAPPING:
                continue

            ioc = NormalizedIoC(
                ioc_value=ind.get("indicator"),
                ioc_type=TYPE_MAPPING[raw_type],
                threat_type="threat_pulse",
                tags=pulse_tags,
                source_feed="AlienVault OTX",
                first_seen=datetime.utcnow(),
                status="online",
                raw_confidence=80
            )
            normalized_iocs.append(ioc)
            if len(normalized_iocs) >= limit:
                return normalized_iocs

    print(f"[+] Successfully normalized {len(normalized_iocs)} OTX indicators.")
    return normalized_iocs