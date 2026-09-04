"""
Data access layer for SOC Causal Correlation system
Provides CRUD operations for Alerts, Incidents, and related entities
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from .models import Alert, Incident, IncidentTechnique, IncidentEntity, MLFeatureStore, ModelVersion
from .database import get_session, get_db_context


class AlertRepository:
    """Repository for Alert operations"""

    @staticmethod
    def create_alert(db: Session, alert_data: Dict[str, Any]) -> Alert:
        """
        Create a new alert record

        Args:
            db: Database session
            alert_data: Dictionary containing alert fields

        Returns:
            Created Alert object
        """
        alert = Alert(**alert_data)
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: str) -> Optional[Alert]:
        """
        Get alert by alert_id

        Args:
            db: Database session
            alert_id: Unique alert identifier

        Returns:
            Alert object if found, None otherwise
        """
        return db.query(Alert).filter(Alert.alert_id == alert_id).first()

    @staticmethod
    def get_alerts_by_timerange(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000
    ) -> List[Alert]:
        """
        Get alerts within a time range

        Args:
            db: Database session
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of records to return

        Returns:
            List of Alert objects
        """
        return (
            db.query(Alert)
            .filter(and_(Alert.timestamp >= start_time, Alert.timestamp <= end_time))
            .order_by(desc(Alert.timestamp))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_alerts_by_entities(
        db: Session,
        entity_type: str,
        entity_value: str,
        limit: int = 1000
    ) -> List[Alert]:
        """
        Get alerts by entity (e.g., user, host, ip)

        Args:
            db: Database session
            entity_type: Type of entity (user, host, ip, etc.)
            entity_value: Value of the entity
            limit: Maximum number of records to return

        Returns:
            List of Alert objects
        """
        entity_column = getattr(Alert, f"entity_{entity_type}", None)
        if entity_column is None:
            raise ValueError(f"Invalid entity type: {entity_type}")

        return (
            db.query(Alert)
            .filter(entity_column == entity_value)
            .order_by(desc(Alert.timestamp))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_recent_alerts(db: Session, limit: int = 100) -> List[Alert]:
        """
        Get most recent alerts

        Args:
            db: Database session
            limit: Maximum number of records to return

        Returns:
            List of Alert objects
        """
        return (
            db.query(Alert)
            .order_by(desc(Alert.timestamp))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_alerts_by_ids(db: Session, alert_ids: List[str]) -> List[Alert]:
        """
        Get alerts by their IDs

        Args:
            db: Database session
            alert_ids: List of alert IDs to retrieve

        Returns:
            List of Alert objects
        """
        if not alert_ids:
            return []
        return db.query(Alert).filter(Alert.alert_id.in_(alert_ids)).all()


class IncidentRepository:
    """Repository for Incident operations"""

    @staticmethod
    def create_incident(db: Session, incident_data: Dict[str, Any]) -> Incident:
        """
        Create a new incident record

        Args:
            db: Database session
            incident_data: Dictionary containing incident fields

        Returns:
            Created Incident object
        """
        # Extract related data for many-to-many relationships
        alert_ids = incident_data.pop('alert_ids', [])
        techniques = incident_data.pop('techniques', [])
        entities = incident_data.pop('entities', [])

        incident = Incident(**incident_data)
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Add associated alerts
        if alert_ids:
            alerts = db.query(Alert).filter(Alert.alert_id.in_(alert_ids)).all()
            incident.alerts = alerts

        # Add techniques
        for technique in techniques:
            incident_technique = IncidentTechnique(
                incident_id=incident.incident_id,
                technique=technique
            )
            db.add(incident_technique)

        # Add entities
        for entity in entities:
            incident_entity = IncidentEntity(
                incident_id=incident.incident_id,
                entity_type=entity['type'],
                entity_value=entity['value']
            )
            db.add(incident_entity)

        db.commit()
        db.refresh(incident)
        return incident

    @staticmethod
    def get_incident_by_id(db: Session, incident_id: str) -> Optional[Incident]:
        """
        Get incident by incident_id

        Args:
            db: Database session
            incident_id: Unique incident identifier

        Returns:
            Incident object if found, None otherwise
        """
        return (
            db.query(Incident)
            .filter(Incident.incident_id == incident_id)
            .first()
        )

    @staticmethod
    def get_incidents_by_timerange(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000
    ) -> List[Incident]:
        """
        Get incidents within a time range

        Args:
            db: Database session
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of records to return

        Returns:
            List of Incident objects
        """
        return (
            db.query(Incident)
            .filter(and_(Incident.time_range_start >= start_time, Incident.time_range_end <= end_time))
            .order_by(desc(Incident.created_at))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_incidents_by_confidence(
        db: Session,
        min_confidence: float = 0.0,
        max_confidence: float = 1.0,
        limit: int = 1000
    ) -> List[Incident]:
        """
        Get incidents by confidence score range

        Args:
            db: Database session
            min_confidence: Minimum confidence score (inclusive)
            max_confidence: Maximum confidence score (inclusive)
            limit: Maximum number of records to return

        Returns:
            List of Incident objects
        """
        return (
            db.query(Incident)
            .filter(and_(Incident.confidence_score >= min_confidence, Incident.confidence_score <= max_confidence))
            .order_by(desc(Incident.confidence_score))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_recent_incidents(db: Session, limit: int = 50) -> List[Incident]:
        """
        Get most recent incidents

        Args:
            db: Database session
            limit: Maximum number of records to return

        Returns:
            List of Incident objects
        """
        return (
            db.query(Incident)
            .order_by(desc(Incident.created_at))
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_incidents_by_ids(db: Session, incident_ids: List[str]) -> List[Incident]:
        """
        Get incidents by their IDs

        Args:
            db: Database session
            incident_ids: List of incident IDs to retrieve

        Returns:
            List of Incident objects
        """
        if not incident_ids:
            return []
        return db.query(Incident).filter(Incident.incident_id.in_(incident_ids)).all()


class MLFeatureRepository:
    """Repository for ML feature operations"""

    @staticmethod
    def create_feature(db: Session, feature_data: Dict[str, Any]) -> MLFeatureStore:
        """
        Create a new ML feature record

        Args:
            db: Database session
            feature_data: Dictionary containing feature fields

        Returns:
            Created MLFeatureStore object
        """
        feature = MLFeatureStore(**feature_data)
        db.add(feature)
        db.commit()
        db.refresh(feature)
        return feature

    @staticmethod
    def get_features_by_incident(db: Session, incident_id: str) -> List[MLFeatureStore]:
        """
        Get all features for a given incident

        Args:
            db: Database session
            incident_id: Incident identifier

        Returns:
            List of MLFeatureStore objects
        """
        return (
            db.query(MLFeatureStore)
            .filter(MLFeatureStore.incident_id == incident_id)
            .all()
        )

    @staticmethod
    def get_latest_features_by_name(db: Session, feature_name: str, limit: int = 1000) -> List[MLFeatureStore]:
        """
        Get latest features by feature name

        Args:
            db: Database session
            feature_name: Name of the feature
            limit: Maximum number of records to return

        Returns:
            List of MLFeatureStore objects
        """
        return (
            db.query(MLFeatureStore)
            .filter(MLFeatureStore.feature_name == feature_name)
            .order_by(desc(MLFeatureStore.computed_at))
            .limit(limit)
            .all()
        )


class ModelVersionRepository:
    """Repository for ML model version operations"""

    @staticmethod
    def create_model_version(db: Session, model_data: Dict[str, Any]) -> ModelVersion:
        """
        Create a new model version record

        Args:
            db: Database session
            model_data: Dictionary containing model version fields

        Returns:
            Created ModelVersion object
        """
        model_version = ModelVersion(**model_data)
        db.add(model_version)
        db.commit()
        db.refresh(model_version)
        return model_version

    @staticmethod
    def get_active_model(db: Session, model_name: str) -> Optional[ModelVersion]:
        """
        Get active model version for a given model name

        Args:
            db: Database session
            model_name: Name of the model (e.g., 'root_cause', 'confidence', 'response')

        Returns:
            ModelVersion object if found, None otherwise
        """
        return (
            db.query(ModelVersion)
            .filter(and_(ModelVersion.model_name == model_name, ModelVersion.is_active == True))
            .first()
        )

    @staticmethod
    def set_model_active(db: Session, model_name: str, version: str) -> bool:
        """
        Set a specific model version as active and deactivate others for the same model

        Args:
            db: Database session
            model_name: Name of the model
            version: Version to set as active

        Returns:
            True if successful, False otherwise
        """
        try:
            # Deactivate all versions for this model
            db.query(ModelVersion).filter(ModelVersion.model_name == model_name).update({ModelVersion.is_active: False})

            # Activate the specified version
            result = db.query(ModelVersion).filter(
                and_(ModelVersion.model_name == model_name, ModelVersion.version == version)
            ).update({ModelVersion.is_active: True})

            db.commit()
            return result > 0
        except Exception as e:
            db.rollback()
            raise e

    @staticmethod
    def get_model_history(db: Session, model_name: str, limit: int = 50) -> List[ModelVersion]:
        """
        Get history of model versions for a given model

        Args:
            db: Database session
            model_name: Name of the model
            limit: Maximum number of records to return

        Returns:
            List of ModelVersion objects
        """
        return (
            db.query(ModelVersion)
            .filter(ModelVersion.model_name == model_name)
            .order_by(desc(ModelVersion.created_at))
            .limit(limit)
            .all()
        )


# Convenience functions for getting repositories with automatic session management
def get_alert_repository() -> AlertRepository:
    """Get AlertRepository instance"""
    return AlertRepository()

def get_incident_repository() -> IncidentRepository:
    """Get IncidentRepository instance"""
    return IncidentRepository()

def get_ml_feature_repository() -> MLFeatureRepository:
    """Get MLFeatureRepository instance"""
    return MLFeatureRepository()

def get_model_version_repository() -> ModelVersionRepository:
    """Get ModelVersionRepository instance"""
    return ModelVersionRepository()