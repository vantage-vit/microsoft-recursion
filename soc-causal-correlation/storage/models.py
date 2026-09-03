"""
SQLAlchemy models for SOC Causal Correlation system
Defines database schema for storing alerts, incidents, and related data
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, Table, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import Optional

Base = declarative_base()

# Association table for many-to-many relationship between Incident and Alert
# We don't have a class for this association, so we define it as a Table
incident_alerts = Table(
    'incident_alerts',
    Base.metadata,
    Column('incident_id', String, ForeignKey('incidents.incident_id'), primary_key=True),
    Column('alert_id', String, ForeignKey('alerts.alert_id'), primary_key=True),
    Column('alert_order', Integer)  # To preserve order if needed
)

class Alert(Base):
    """
    Stores normalized alert data from ingestion pipeline
    Matches Alert Pydantic model from schema.py
    """
    __tablename__ = 'alerts'

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)

    # Core alert fields
    timestamp = Column(DateTime, nullable=True, index=True)
    source_product = Column(String, nullable=False, index=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)  # low, medium, high, critical, unknown
    raw_text = Column(Text, nullable=False)
    mitre_technique = Column(String, nullable=True, index=True)

    # Entity fields (flattened for easier querying)
    entity_user = Column(String, nullable=True, index=True)
    entity_host = Column(String, nullable=True, index=True)
    entity_ip = Column(String, nullable=True, index=True)
    entity_process = Column(String, nullable=True, index=True)
    entity_file = Column(String, nullable=True, index=True)
    entity_cloud_role = Column(String, nullable=True, index=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    incidents = relationship("Incident", secondary=incident_alerts, back_populates="alerts")

    # Indexes for common query patterns
    __table_args__ = (
        Index('idx_alert_timestamp_source', 'timestamp', 'source_product'),
        Index('idx_alert_entities', 'entity_user', 'entity_host', 'entity_ip'),
        Index('idx_alert_mitre_time', 'mitre_technique', 'timestamp'),
    )

    def __repr__(self):
        return f"<Alert(alert_id='{self.alert_id}', source='{self.source_product}', severity='{self.severity}')>"

class Incident(Base):
    """
    Stores correlated incident data from analysis pipeline
    Matches Incident Pydantic model from schema.py
    """
    __tablename__ = 'incidents'

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, unique=True, index=True, nullable=False)
    root_cause_alert_id = Column(String, ForeignKey('alerts.alert_id'), nullable=True, index=True)

    # Incident characteristics
    confidence_score = Column(Float, nullable=False, default=0.0)  # 0.0-1.0
    recommended_action = Column(Text, nullable=True)
    hypothesis = Column(Text, nullable=True)

    # Time range
    time_range_start = Column(DateTime, nullable=True)
    time_range_end = Column(DateTime, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    root_cause_alert = relationship("Alert", foreign_keys=[root_cause_alert_id])
    alerts = relationship("Alert", secondary=incident_alerts, back_populates="incidents")
    techniques = relationship("IncidentTechnique", back_populates="incident", cascade="all, delete-orphan")
    entities = relationship("IncidentEntity", back_populates="incident", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_incident_time_range', 'time_range_start', 'time_range_end'),
        Index('idx_incident_confidence', 'confidence_score'),
        Index('idx_incident_root_cause', 'root_cause_alert_id'),
    )

    def __repr__(self):
        return f"<Incident(incident_id='{self.incident_id}', confidence={self.confidence_score:.2f}, alerts={len(self.alerts)})>"

class IncidentTechnique(Base):
    """
    Stores MITRE techniques associated with incidents
    """
    __tablename__ = 'incident_techniques'

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey('incidents.incident_id'), nullable=False, index=True)
    technique = Column(String, nullable=False, index=True)

    # Relationship
    incident = relationship("Incident", back_populates="techniques")

    # Indexes
    __table_args__ = (
        Index('idx_incident_technique', 'incident_id', 'technique'),
    )

    def __repr__(self):
        return f"<IncidentTechnique(incident_id='{self.incident_id}', technique='{self.technique}')>"

class IncidentEntity(Base):
    """
    Stores entities associated with incidents
    """
    __tablename__ = 'incident_entities'

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey('incidents.incident_id'), nullable=False, index=True)
    entity_type = Column(String, nullable=False, index=True)  # user, host, ip, process, file, cloud_role
    entity_value = Column(String, nullable=False, index=True)

    # Relationship
    incident = relationship("Incident", back_populates="entities")

    # Indexes
    __table_args__ = (
        Index('idx_incident_entity_type_value', 'entity_type', 'entity_value'),
        Index('idx_incident_entity_incident', 'incident_id', 'entity_type'),
    )

    def __repr__(self):
        return f"<IncidentEntity(incident_id='{self.incident_id}', type='{self.entity_type}', value='{self.entity_value}')>"

class MLFeatureStore(Base):
    """
    Stores engineered features for ML models
    """
    __tablename__ = 'ml_features'

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey('incidents.incident_id'), nullable=False, index=True)
    feature_name = Column(String, nullable=False, index=True)
    feature_value = Column(String, nullable=True)  # Stored as string for flexibility
    feature_type = Column(String, nullable=False)  # temporal, structural, technical, entity, historical
    computed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    incident = relationship("Incident")

    # Indexes
    __table_args__ = (
        Index('idx_ml_features_incident_name', 'incident_id', 'feature_name'),
        Index('idx_ml_features_type', 'feature_type'),
        Index('idx_ml_features_computed', 'computed_at'),
    )

    def __repr__(self):
        return f"<MLFeatureStore(incident_id='{self.incident_id}', feature='{self.feature_name}', type='{self.feature_type}')>"

class ModelVersion(Base):
    """
    Tracks ML model versions and performance metrics
    """
    __tablename__ = 'model_versions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    model_name = Column(String, nullable=False, index=True)  # root_cause, confidence, response
    version = Column(String, nullable=False)
    model_path = Column(String, nullable=False)  # Path to serialized model
    performance_metrics = Column(String, nullable=True)  # JSON string of metrics
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Indexes
    __table_args__ = (
        Index('idx_model_version_name_active', 'model_name', 'is_active'),
        Index('idx_model_version_created', 'created_at'),
    )

    def __repr__(self):
        return f"<ModelVersion(name='{self.model_name}', version='{self.version}', active={self.is_active})>"