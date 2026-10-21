import math
import re
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, List, Union
import pandas as pd
import tldextract

# High-abuse top-level domains frequently seen in phishing & C2 infrastructure
SUSPICIOUS_TLDS = {
    "tk", "top", "xyz", "gq", "ml", "cf", "ga", "cn", "ru",
    "work", "click", "zip", "mov", "rest", "fit", "cam", "icu"
}

# High-risk tokens seen in malware delivery URLs (URLHaus) and phishing lures
SUSPICIOUS_KEYWORDS = [
    "mozi", "mirai", "bin.sh", ".elf", ".exe", ".bat", ".scr", "wget",
    "chmod", "login", "verify", "secure", "account", "update", "banking",
    "wp-admin", "cmd", "shell", "payload", "dropper", "loader"
]

IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "length",
    "host_length",
    "path_length",
    "shannon_entropy",
    "host_entropy",
    "digit_ratio",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "special_char_count",
    "uses_ip_host",
    "has_non_standard_port",
    "has_suspicious_tld",
    "suspicious_keyword_count",
]


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon Entropy (bits per character) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_ioc_features(ioc_value: str) -> Dict[str, float]:
    """
    Converts a raw URL, Domain, or IPv4 indicator into a 14-dimensional numerical dictionary.
    """
    raw = ioc_value.strip()

    # Ensure urlparse can extract hostname properly even if scheme (http://) is missing
    parse_target = raw if "://" in raw else f"http://{raw}"
    parsed = urlparse(parse_target)

    hostname = parsed.hostname or raw
    path = parsed.path or ""
    port = parsed.port

    # Extract TLD using tldextract
    ext = tldextract.extract(hostname)
    tld = (ext.suffix or "").lower()

    total_len = len(raw)
    digit_count = sum(c.isdigit() for c in raw)
    special_chars = sum(c in "@?=%&_~;:$!*" for c in raw)

    # Check if hostname is a raw IPv4 address
    is_ip_host = 1.0 if IPV4_REGEX.match(hostname) else 0.0

    # Check for non-standard ports (either in URL or 'port:XXXX' format)
    non_std_port = 1.0 if (port and port not in (80, 443)) else 0.0

    # Count matching suspicious keywords (case-insensitive)
    raw_lower = raw.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in raw_lower)

    return {
        "length": float(total_len),
        "host_length": float(len(hostname)),
        "path_length": float(len(path)),
        "shannon_entropy": calculate_shannon_entropy(raw),
        "host_entropy": calculate_shannon_entropy(hostname),
        "digit_ratio": round(digit_count / max(total_len, 1), 4),
        "dot_count": float(raw.count(".")),
        "hyphen_count": float(raw.count("-")),
        "slash_count": float(raw.count("/")),
        "special_char_count": float(special_chars),
        "uses_ip_host": is_ip_host,
        "has_non_standard_port": non_std_port,
        "has_suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        "suspicious_keyword_count": float(keyword_hits),
    }


def extract_features_dataframe(ioc_list: List[str]) -> pd.DataFrame:
    """
    Batch-converts a list of IoC strings into a Pandas DataFrame with ordered feature columns.
    """
    records = [extract_ioc_features(ioc) for ioc in ioc_list]
    return pd.DataFrame(records, columns=FEATURE_NAMES)


if __name__ == "__main__":
    from app.database import SessionLocal, IoCRecord

    db = SessionLocal()
    try:
        db_iocs = db.query(IoCRecord).limit(5).all()
        print(f"=== TESTING FEATURE EXTRACTION ON {len(db_iocs)} LIVE DB IOCs ===\n")

        for record in db_iocs:
            feats = extract_ioc_features(record.ioc_value)
            print(f"IoC     : {record.ioc_value}")
            print(f"Type    : {record.ioc_type.upper()} | Threat: {record.threat_type}")
            print(
                f"Vector  : Entropy={feats['shannon_entropy']} | "
                f"DigitRatio={feats['digit_ratio']} | "
                f"IP_Host={int(feats['uses_ip_host'])} | "
                f"NonStdPort={int(feats['has_non_standard_port'])} | "
                f"Keywords={int(feats['suspicious_keyword_count'])}\n"
            )

        # Compare average feature profile: Your 31 Malicious IoCs vs Benign Websites
        all_malicious = [r.ioc_value for r in db.query(IoCRecord).all()]
        benign_samples = [
            "https://www.google.com/search?q=cybersecurity",
            "https://github.com/tiangolo/fastapi",
            "https://docs.python.org/3/library/urllib.parse.html",
            "https://stackoverflow.com/questions/tagged/machine-learning",
            "https://en.wikipedia.org/wiki/Threat_intelligence",
        ]

        mal_df = extract_features_dataframe(all_malicious)
        ben_df = extract_features_dataframe(benign_samples)

        comparison = pd.DataFrame({
            "Malicious_DB_Mean": mal_df.mean().round(3),
            "Benign_Sample_Mean": ben_df.mean().round(3),
        })
        print("=== FEATURE SEPARATION: YOUR 31 DB IOCs VS BENIGN SAMPLES ===")
        print(comparison.to_string())
    finally:
        db.close()