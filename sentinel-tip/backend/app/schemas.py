from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class NormalizedIoC(BaseModel):
    ioc_value: str = Field(..., description="The raw indicator (URL, IP, Domain, or Hash)")
    ioc_type: str = Field(..., description="url, ipv4, domain, or sha256")
    threat_type: str = Field(..., description="e.g., malware_download, phishing, botnet_c2")
    tags: List[str] = Field(default_factory=list, description="Malware family or threat tags")
    source_feed: str = Field(..., description="Name of the OSINT feed")
    first_seen: Optional[datetime] = None
    status: str = Field(default="online", description="online, offline, or unknown")
    raw_confidence: int = Field(default=75, ge=0, le=100, description="Initial feed confidence (0-100)")