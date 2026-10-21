import re
from typing import Dict, List, Any

# MITRE ATT&CK behavioral keyword mapping
MITRE_ATTACK_MAP = [
    {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "keywords": ["phishing", "spearphishing", "credential harvesting", "lure", "spoofed email"]
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "keywords": ["powershell", "bash", "bin.sh", "cmd.exe", "wget", "curl", "shell script"]
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "keywords": ["c2", "command and control", "beacon", "botnet", "callback", "cobalt strike"]
    },
    {
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "keywords": ["dropper", "loader", "payload", "second-stage", "malware download", ".elf", ".exe"]
    },
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "keywords": ["ransomware", "encrypt", "extortion", "decryptor", "lockbit"]
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "keywords": ["cve-", "rce", "remote code execution", "zero-day", "sql injection", "exploit"]
    }
]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|gq|work|icu|info|biz)\b", re.IGNORECASE)


def refang_text(raw_text: str) -> str:
    """Converts defanged threat report syntax (hxxp, [.], (:)) into standard parseable strings."""
    cleaned = raw_text.replace("[.]", ".").replace("(.)", ".")
    cleaned = re.sub(r"\bhxxps\b", "https", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bhxxp\b", "http", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("[:]", ":")
    return cleaned


def extract_threat_intel_from_text(raw_text: str) -> Dict[str, Any]:
    """
    Extracts structured IoCs and MITRE ATT&CK techniques from unstructured security text.
    """
    cleaned_text = refang_text(raw_text)
    lower_text = cleaned_text.lower()

    urls = sorted(list(set(URL_REGEX.findall(cleaned_text))))
    ipv4s = sorted(list(set(IPV4_REGEX.findall(cleaned_text))))
    cves = sorted(list(set(cve.upper() for cve in CVE_REGEX.findall(cleaned_text))))
    sha256s = sorted(list(set(SHA256_REGEX.findall(cleaned_text))))
    domains = sorted(list(set(DOMAIN_REGEX.findall(cleaned_text))))

    # Match MITRE ATT&CK techniques
    detected_ttps: List[Dict[str, str]] = []
    for item in MITRE_ATTACK_MAP:
        matched_kw = [kw for kw in item["keywords"] if kw in lower_text]
        if matched_kw:
            detected_ttps.append({
                "technique_id": item["technique_id"],
                "name": item["name"],
                "tactic": item["tactic"],
                "matched_keywords": matched_kw
            })

    return {
        "extracted_iocs": {
            "urls": urls,
            "ipv4s": ipv4s,
            "domains": domains,
            "sha256_hashes": sha256s,
            "cves": cves
        },
        "mitre_attack_ttps": detected_ttps,
        "total_indicators_found": len(urls) + len(ipv4s) + len(domains) + len(sha256s) + len(cves)
    }


if __name__ == "__main__":
    sample_report = """
    Incident Advisory: Adversaries exploited CVE-2024-3400 using a spearphishing lure to deploy
    a second-stage dropper via powershell. The script executed wget against hxxp://185.220.101[.]45:8080/bin.sh
    and established a Cobalt Strike C2 beacon to update-login-portal[.]top and 91.215.85[.]142.
    Payload SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    result = extract_threat_intel_from_text(sample_report)
    print("=== NLP THREAT REPORT EXTRACTION TEST ===")
    print("Extracted IoCs :", result["extracted_iocs"])
    print("MITRE ATT&CK   :", [f"{t['technique_id']} ({t['name']})" for t in result["mitre_attack_ttps"]])