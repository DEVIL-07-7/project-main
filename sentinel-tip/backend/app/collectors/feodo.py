import requests
from datetime import datetime
from typing import List
from app.schemas import NormalizedIoC

FEODO_JSON_ENDPOINT = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

def fetch_feodo_ips(limit: int = 25) -> List[NormalizedIoC]:
    """
    Fetches active Botnet Command & Control (C2) IPv4 addresses from Feodo Tracker.
    """
    print("[*] Fetching active Botnet C2 IPs from Feodo Tracker...")
    response = requests.get(FEODO_JSON_ENDPOINT, timeout=30)
    response.raise_for_status()

    data = response.json()
    normalized_iocs: List[NormalizedIoC] = []

    for entry in data[:limit]:
        ip_val = entry.get("ip_address")
        if not ip_val:
            continue

        malware_family = entry.get("malware", "Unknown Botnet")
        port = entry.get("port")
        status = entry.get("status", "online")
        first_seen_str = entry.get("first_seen")

        try:
            first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            first_seen = datetime.utcnow()

        tags = [malware_family]
        if port:
            tags.append(f"port:{port}")

        ioc = NormalizedIoC(
            ioc_value=ip_val,
            ioc_type="ipv4",
            threat_type="botnet_c2",
            tags=tags,
            source_feed="Abuse.ch FeodoTracker",
            first_seen=first_seen,
            status=status,
            raw_confidence=90 if status == "online" else 70
        )
        normalized_iocs.append(ioc)

    print(f"[+] Successfully normalized {len(normalized_iocs)} Botnet C2 IPv4 indicators.")
    return normalized_iocs