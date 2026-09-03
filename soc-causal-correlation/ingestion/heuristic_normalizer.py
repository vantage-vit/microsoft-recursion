"""Deterministic local normalizer for demos and offline use.

It intentionally favors transparent, conservative extraction over pretending to
replace a SIEM parser or an LLM.  The LLM normalizer remains available when an
API key is configured.
"""

import re
from datetime import datetime
from typing import Optional

try:
    from ..schema import Alert, AlertEntities
except ImportError:
    from schema import Alert, AlertEntities


TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST = re.compile(r"\b(?:DESKTOP|LAPTOP|SERVER|HOST)-[A-Za-z0-9-]+\b", re.I)
ROLE = re.compile(r"\barn:aws:iam::[^\s]+", re.I)
MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def normalize_alert_locally(raw_text: str, alert_id: str) -> Alert:
    """Extract common alert fields without making a network request."""
    text = raw_text.strip()
    lower = text.lower()
    timestamp = _extract_timestamp(text)
    entities = AlertEntities(
        user=_first(EMAIL, text),
        host=_first(HOST, text),
        ip=_first(IP_ADDRESS, text),
        process="powershell.exe" if "powershell" in lower else None,
        cloud_role=_first(ROLE, text),
    )
    source = _source_for(lower)
    alert_type, severity, technique = _classification_for(lower)
    explicit_technique = _first(MITRE, text)
    return Alert(
        alert_id=alert_id,
        timestamp=timestamp,
        source_product=source,
        alert_type=alert_type,
        severity=severity,
        entities=entities,
        raw_text=text,
        mitre_technique=explicit_technique or technique,
    )


def _first(pattern: re.Pattern[str], text: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(0) if match else None


def _extract_timestamp(text: str) -> Optional[datetime]:
    match = TIMESTAMP.search(text)
    return datetime.fromisoformat(match.group(1).replace(" ", "T")) if match else None


def _source_for(text: str) -> str:
    if "firewall" in text:
        return "Firewall"
    if "aws" in text or "cloud" in text:
        return "Cloud"
    if "edr" in text or "endpoint" in text:
        return "Endpoint (EDR)"
    if "identity" in text or "login" in text:
        return "Identity Platform"
    return "Unknown"


def _classification_for(text: str) -> tuple[str, str, Optional[str]]:
    if "failed login" in text or "brute force" in text:
        return "Failed login", "medium", "T1110"
    if "successful login" in text or "unrecognized device" in text:
        return "Suspicious login", "medium", "T1078"
    if "powershell" in text or "encoded command" in text:
        return "Suspicious PowerShell execution", "high", "T1059.001"
    if "role assumed" in text or "cloud role" in text:
        return "Cloud role assumption", "high", "T1078.004"
    if "outbound transfer" in text or "exfiltration" in text:
        return "Possible data exfiltration", "critical", "T1041"
    if "malware" in text or "ransomware" in text:
        return "Malware detection", "high", None
    return "Unclassified alert", "unknown", None
