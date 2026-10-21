import csv
import io
import requests
from datetime import datetime
from typing import List
from app.schemas import NormalizedIoC

URLHAUS_CSV_ENDPOINT = "https://urlhaus.abuse.ch/downloads/csv_recent/"

def fetch_urlhaus_feed(limit: int = 25) -> List[NormalizedIoC]:
    """
    Fetches recent live malicious URLs from Abuse.ch URLHaus
    and normalizes them into our standard IoC schema.
    """
    print(f"[*] Fetching live threat feed from URLHaus...")
    response = requests.get(URLHAUS_CSV_ENDPOINT, timeout=30)
    response.raise_for_status()

    # Filter out comment lines starting with '#'
    raw_lines = [
        line for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    reader = csv.reader(io.StringIO("\n".join(raw_lines)))
    normalized_iocs: List[NormalizedIoC] = []

    for row in reader:
        # CSV format: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 7:
            continue

        _, date_added_str, url_val, url_status, _, threat, tags_str, *_ = row

        try:
            first_seen = datetime.strptime(date_added_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            first_seen = datetime.utcnow()

        tags = [t.strip() for t in tags_str.split(",") if t.strip() and t.strip() != "None"]

        ioc = NormalizedIoC(
            ioc_value=url_val,
            ioc_type="url",
            threat_type=threat or "malware_download",
            tags=tags,
            source_feed="Abuse.ch URLHaus",
            first_seen=first_seen,
            status=url_status or "unknown",
            raw_confidence=85 if url_status == "online" else 60
        )
        normalized_iocs.append(ioc)

        if len(normalized_iocs) >= limit:
            break

    print(f"[+] Successfully normalized {len(normalized_iocs)} live malicious URLs.")
    return normalized_iocs


if __name__ == "__main__":
    sample_iocs = fetch_urlhaus_feed(limit=5)
    print("\n--- SAMPLE NORMALIZED THREAT INDICATORS ---")
    for idx, item in enumerate(sample_iocs, 1):
        print(f"{idx}. [{item.ioc_type.upper()}] {item.ioc_value}")
        print(f"   Threat: {item.threat_type} | Status: {item.status} | Tags: {item.tags} | Confidence: {item.raw_confidence}%\n")