"""Shared, validated data contracts for the correlation pipeline."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AlertEntities(BaseModel):
    """Entities extracted from an alert that can connect related activity."""

    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    process: Optional[str] = None
    file: Optional[str] = None
    cloud_role: Optional[str] = None


class Alert(BaseModel):
    """A normalized alert used consistently by every pipeline stage."""

    alert_id: str
    timestamp: Optional[datetime] = None
    source_product: str
    alert_type: str
    severity: str = "unknown"
    entities: AlertEntities = Field(default_factory=AlertEntities)
    raw_text: str
    mitre_technique: Optional[str] = None

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: object) -> str:
        aliases = {"med": "medium", "hi": "high", "crit": "critical", "lo": "low"}
        normalized = aliases.get(str(value or "unknown").lower(), str(value or "unknown").lower())
        return normalized if normalized in {"low", "medium", "high", "critical", "unknown"} else "unknown"

    def entity_dict(self) -> Dict[str, str]:
        """Return only populated entity fields."""
        return {key: value for key, value in self.entities.model_dump().items() if value}


class Incident(BaseModel):
    """A correlated group of alerts and its recommended investigation response."""

    incident_id: str
    alert_ids: List[str] = Field(default_factory=list)
    root_cause_alert_id: Optional[str] = None
    participating_entities: Dict[str, List[str]] = Field(default_factory=dict)
    time_range: Dict[str, Optional[datetime]] = Field(default_factory=lambda: {"start": None, "end": None})
    attack_techniques: List[str] = Field(default_factory=list)
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    recommended_action: str = ""
    hypothesis: str = ""


class NormalizationResult(BaseModel):
    success: bool
    alert: Optional[Alert] = None
    error_message: Optional[str] = None
    retry_suggested: bool = False
