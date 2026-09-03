"""
Response recommender: rule table: blast radius + entity type -> action tier
"""

from typing import Dict, Any, List, Optional
try:
    # Try relative imports (when used as package)
    from ..schema import Incident, Alert
    from ..graph.clustering import summarize_incident
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Incident, Alert
    from graph.clustering import summarize_incident

class ResponseRecommender:
    def __init__(self):
        # Rule table mapping (entity_type, blast_radius, confidence) -> action
        self.response_rules = {
            # High confidence, limited blast radius -> precise actions
            ('user', 'low', 'high'): "Disable specific user session or token",
            ('user', 'low', 'medium'): "Force password reset and MFA re-enrollment",
            ('user', 'low', 'low'): "Flag for manual review - possible compromised credentials",

            ('host', 'low', 'high'): "Isolate specific host from network",
            ('host', 'low', 'medium'): "Collect forensic image and run antivirus scan",
            ('host', 'low', 'low'): "Monitor host for suspicious behavior",

            ('ip', 'low', 'high'): "Block specific IP address at firewall",
            ('ip', 'low', 'medium'): "Rate limit connections from IP address",
            ('ip', 'low', 'low'): "Log and monitor traffic from IP address",

            ('cloud_role', 'low', 'high'): "Revoke specific cloud role/session",
            ('cloud_role', 'low', 'medium'): "Rotate cloud credentials and review access logs",
            ('cloud_role', 'low', 'low'): "Audit cloud role usage and permissions",

            # Medium blast radius -> broader but targeted actions
            ('user', 'medium', 'high'): "Disable user account and investigate lateral movement",
            ('user', 'medium', 'medium'): "Reset user password and review all active sessions",
            ('user', 'medium', 'low'): "Increase monitoring on user account and associated hosts",

            ('host', 'medium', 'high'): "Isolate host subnet and investigate breach scope",
            ('host', 'medium', 'medium'): "Scan host segment for indicators of compromise",
            ('host', 'medium', 'low'): "Increase monitoring on host segment",

            # High blast radius -> conservative, evidence-gathering actions
            ('user', 'high', 'high'): "Initiate incident response - likely account compromise",
            ('user', 'high', 'medium'): "Gather evidence before taking disruptive action",
            ('user', 'high', 'low'): "Increase monitoring and alert on user activity",

            # Default rules when specific combinations aren't found
            ('default', 'low', 'high'): "Take precise containment action based on evidence",
            ('default', 'low', 'medium'): "Investigate further before taking action",
            ('default', 'low', 'low'): "Monitor and log for additional evidence",
            ('default', 'medium', 'high'): "Take targeted action with minimal business disruption",
            ('default', 'medium', 'medium'): "Investigate scope before broader action",
            ('default', 'medium', 'low'): "Enhanced monitoring and logging",
            ('default', 'high', 'high'): "Initiate formal incident response procedures",
            ('default', 'high', 'medium'): "Consult with incident response team before action",
            ('default', 'high', 'low'): "Increase monitoring and prepare for possible IR",
        }

    def recommend_response(self, incident: Incident, incident_summary: Dict[str, Any]) -> str:
        """
        Recommend a response action based on incident characteristics.

        Args:
            incident: Incident object with correlated alerts
            incident_summary: Summary from clustering phase

        Returns:
            Recommended action string
        """
        # Determine blast radius based on incident scope
        blast_radius = self._calculate_blast_radius(incident_summary)

        # Determine primary entity type involved
        primary_entity_type = self._get_primary_entity_type(incident_summary)

        # Get confidence from incident
        confidence_level = self._confidence_to_level(incident.confidence_score)

        # Look up rule
        rule_key = (primary_entity_type, blast_radius, confidence_level)
        action = self.response_rules.get(rule_key)

        if not action:
            # Try with default entity type
            rule_key = ('default', blast_radius, confidence_level)
            action = self.response_rules.get(rule_key)

        if not action:
            # Final fallback
            action = self.response_rules.get(('default', 'medium', 'medium'),
                                          "Analyze incident further and consult security team")

        # Customize action based on incident specifics
        customized_action = self._customize_action(action, incident, incident_summary)
        return customized_action

    def _calculate_blast_radius(self, incident_summary: Dict[str, Any]) -> str:
        """
        Calculate blast radius based on incident size and scope.

        Returns:
            'low', 'medium', or 'high'
        """
        alert_count = incident_summary.get('alert_count', 0)
        entity_count = incident_summary.get('entity_count', 0)
        source_count = len(incident_summary.get('sources', []))
        time_span = incident_summary.get('time_span_hours', 0) or 0

        # Scoring factors
        size_score = min(alert_count / 10.0, 1.0)  # Normalize to 0-1, 10+ alerts = high
        entity_score = min(entity_count / 5.0, 1.0)  # Normalize to 0-1, 5+ entities = high
        source_score = min(source_count / 3.0, 1.0)  # Normalize to 0-1, 3+ sources = high
        time_score = min(time_span / 24.0, 1.0)  # Normalize to 0-1, 24+ hours = high

        # Weighted average
        blast_score = (size_score * 0.3 + entity_score * 0.25 +
                      source_score * 0.25 + time_score * 0.2)

        if blast_score < 0.33:
            return 'low'
        elif blast_score < 0.66:
            return 'medium'
        else:
            return 'high'

    def _get_primary_entity_type(self, incident_summary: Dict[str, Any]) -> str:
        """Get the primary entity type involved in the incident."""
        entity_types = incident_summary.get('entity_types', {})

        if not entity_types:
            return 'unknown'

        # Return the entity type with the highest count
        primary_type = max(entity_types.items(), key=lambda x: x[1])[0]
        return primary_type

    def _confidence_to_level(self, confidence: float) -> str:
        """Convert numeric confidence to categorical level."""
        if confidence >= 0.7:
            return 'high'
        elif confidence >= 0.4:
            return 'medium'
        else:
            return 'low'

    def _customize_action(self, base_action: str, incident: Incident,
                         incident_summary: Dict[str, Any]) -> str:
        """Customize the base action with incident-specific details."""
        # Add incident ID and confidence
        customized = f"[INCIDENT {incident.incident_id}] {base_action}"

        # Add confidence if available
        if incident.confidence_score > 0:
            customized += f" (confidence: {incident.confidence_score:.0%})"

        # Add root cause info if available
        if incident.root_cause_alert_id:
            customized += f" - Targeting root cause: {incident.root_cause_alert_id}"

        # Add techniques if available
        techniques = incident_summary.get('techniques', [])
        if techniques:
            tech_str = ', '.join(techniques[:2])  # Show first 2 techniques
            if len(techniques) > 2:
                tech_str += f" +{len(techniques)-2} more"
            customized += f" | Techniques: {tech_str}"

        return customized

    def get_alternative_actions(self, incident: Incident,
                              incident_summary: Dict[str, Any]) -> List[str]:
        """
        Get alternative response actions for consideration.

        Returns:
            List of alternative action strings
        """
        alternatives = []
        blast_radius = self._calculate_blast_radius(incident_summary)
        primary_entity_type = self._get_primary_entity_type(incident_summary)
        confidence_level = self._confidence_to_level(incident.confidence_score)

        # Look for similar actions with different confidence levels
        for (entity_type, br, conf), action in self.response_rules.items():
            if (entity_type == primary_entity_type or entity_type == 'default') and \
               br == blast_radius and conf != confidence_level:
                alternatives.append(f"[ALTERNATIVE] {action}")

        # Limit alternatives
        return alternatives[:3]

# Convenience function for direct use
def recommend_response(incident: Incident, incident_summary: Dict[str, Any]) -> str:
    """Convenience function to recommend response."""
    recommender = ResponseRecommender()
    return recommender.recommend_response(incident, incident_summary)

if __name__ == "__main__":
    # Test the response recommender
    from datetime import datetime

    # Create a test incident
    test_incident = Incident(
        incident_id="INC-001",
        alert_ids=["alert_001", "alert_002", "alert_003"],
        root_cause_alert_id="alert_001",
        participating_entities={
            "user": ["j.suresh@acmecorp.com"],
            "host": ["DESKTOP-7QK41"],
            "cloud_role": ["arn:aws:iam::role/finance-read"]
        },
        time_range={"start": datetime.now(), "end": datetime.now()},
        attack_techniques=["T1110", "T1078", "T1059.001", "T1041"],
        confidence_score=0.85,
        recommended_action="",
        hypothesis=""
    )

    # Create a test incident summary
    test_summary = {
        'incident_id': 'INC-001',
        'alert_count': 3,
        'entity_count': 3,
        'alerts': [],
        'time_span_hours': 2.5,
        'sources': ['Identity Platform', 'Endpoint (EDR)', 'Cloud (AWS)'],
        'severity_distribution': {'medium': 2, 'high': 1},
        'techniques': ['T1110', 'T1078', 'T1059.001', 'T1041'],
        'entity_types': {'user': 1, 'host': 1, 'cloud_role': 1},
        'density': 0.6
    }

    recommender = ResponseRecommender()
    action = recommender.recommend_response(test_incident, test_summary)
    print(f"Recommended action: {action}")

    alternatives = recommender.get_alternative_actions(test_incident, test_summary)
    print("Alternative actions:")
    for alt in alternatives:
        print(f"  {alt}")