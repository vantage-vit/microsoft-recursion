"""
Pydantic models — Alert, Entities, Incident
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
from datetime import datetime

class AlertEntities(BaseModel):
    """Entity fields that can be extracted from alerts"""
    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    process: Optional[str] = None
    file: Optional[str] = None
    cloud_role: Optional[str] = None
    # Add other entity types as needed

class Alert(BaseModel):
    """Schema for normalized security alerts"""
    alert_id: str = Field(..., description="Unique identifier for the alert")
    timestamp: Optional[datetime] = Field(None, description="When the alert occurred")
    source_product: str = Field(..., description="Security product that generated the alert")
    alert_type: str = Field(..., description="Type of alert (e.g., 'Failed login', 'Malware detected')")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    entities: AlertEntities = Field(default_factory=AlertEntities, description="Entities mentioned in the alert")
    raw_text: str = Field(..., description="Original alert text")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique identifier if applicable")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

class Incident(BaseModel):
    """Schema for correlated incidents"""
    incident_id: str = Field(..., description="Unique identifier for the incident")
    alert_ids: List[str] = Field(..., description="List of alert IDs that belong to this incident")
    root_cause_alert_id: Optional[str] = Field(None, description="Alert ID identified as the root cause")
    participating_entities: Dict[str, List[str]] = Field(default_factory=dict, description="Entities involved, grouped by type")
    time_range: Dict[str, Optional[datetime]] = Field(default_factory=lambda: {"start": None, "end": None}, description="Time range of the incident")
    attack_techniques: List[str] = Field(default_factory=list, description="MITRE techniques observed in the incident")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Confidence in the correlation")
    recommended_action: str = Field("", description="Recommended response action")
    hypothesis: str = Field("", description="Alternative hypothesis or explanation")

class NormalizationResult(BaseModel):
    """Result of alert normalization process"""
    success: bool
    alert: Optional[Alert] = None
    error_message: Optional[str] = None
    retry_suggested: bool = False