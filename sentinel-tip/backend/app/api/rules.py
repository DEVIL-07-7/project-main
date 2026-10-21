import re
from datetime import datetime
from typing import Dict
from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/rules", tags=["Automated Rule Generation"])


class RuleRequest(BaseModel):
    ioc_value: str = Field(..., description="Indicator value")
    ioc_type: str = Field(default="url", description="url, ipv4, domain, sha256")
    threat_name: str = Field(default="ThreatOps_Identified_Threat")


@router.post("/generate")
def generate_detection_rules(payload: RuleRequest) -> Dict[str, str]:
    ioc = payload.ioc_value.strip()
    threat = re.sub(r"[^a-zA-Z0-9_]", "_", payload.threat_name)
    timestamp = datetime.utcnow().strftime("%Y/%m/%d")

    sigma_rule = f"""title: Detection of {threat} Activity
id: {re.sub(r'[^0-9a-f]', '', ioc)[:32].ljust(32, 'a')}
status: experimental
description: Auto-generated detection rule from ThreatOps AI Engine for {ioc}
date: {timestamp}
author: ThreatOps Automated Detection
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp|contains: '{ioc}'
    condition: selection
level: high
"""

    yara_rule = f"""rule ThreatOps_{threat} {{
    meta:
        description = "Identifies indicators associated with {threat}"
        author = "ThreatOps Auto-Generator"
        date = "{timestamp}"
        threat_level = "Critical"
    strings:
        $ioc_string = "{ioc}" ascii wide nocase
    condition:
        $ioc_string
}}"""

    suricata_rule = f'alert ip any any -> {ioc if payload.ioc_type == "ipv4" else "$EXTERNAL_NET"} any (msg:"THREATOPS Block - {threat} [{ioc}]"; flow:established,to_server; content:"{ioc}"; classtype:trojan-activity; sid:9000101; rev:1;)'

    snort_rule = f'drop tcp $HOME_NET any -> any any (msg:"THREATOPS SNORT DROP - {ioc}"; content:"{ioc}"; nocase; sid:1000901; rev:1;)'

    return {
        "sigma": sigma_rule,
        "yara": yara_rule,
        "suricata": suricata_rule,
        "snort": snort_rule,
    }