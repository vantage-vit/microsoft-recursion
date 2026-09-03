"""Streamlit interface for the local SOC alert-correlation workflow."""

import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    from pipeline import alerts_from_text, analyze_alerts
    from viz.graph_render import IncidentGraphRenderer
except ImportError:
    # Fallback for when running as script
    from .pipeline import alerts_from_text, analyze_alerts
    from .viz.graph_render import IncidentGraphRenderer

# Import storage components for enhanced reporting
try:
    from storage.database import get_db_context
    from storage.repository import IncidentRepository, AlertRepository
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False
    # Create a dummy logger for when storage is not available
    import logging
    logging.getLogger(__name__).addHandler(logging.NullHandler())

SAMPLE_ALERTS = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
2023-01-15 09:24:55 Cloud (AWS): New cloud role assumed - arn:aws:iam::role/finance-read
2023-01-15 09:41:03 Firewall: Outbound transfer - 2.3GB to unrecognized IP 203.0.113.44"""


def get_db_incident_details(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch detailed incident information from the database.

    Args:
        incident_id: The incident identifier

    Returns:
        Dictionary with incident details or None if not available/error
    """
    if not STORAGE_AVAILABLE:
        return None

    try:
        with get_db_context() as db:
            incident_repo = IncidentRepository()
            db_incident = incident_repo.get_incident_by_id(db, incident_id)
            if db_incident:
                # Convert to dictionary for easier access
                return {
                    "incident_id": db_incident.incident_id,
                    "root_cause_alert_id": db_incident.root_cause_alert_id,
                    "confidence_score": db_incident.confidence_score,
                    "recommended_action": db_incident.recommended_action,
                    "hypothesis": db_incident.hypothesis,
                    "time_range_start": db_incident.time_range_start,
                    "time_range_end": db_incident.time_range_end,
                    "alert_ids": [alert.alert_id for alert in db_incident.alerts],
                    "techniques": [tech.technique for tech in db_incident.techniques],
                    "entities": [
                        {"type": ent.entity_type, "value": ent.entity_value}
                        for ent in db_incident.entities
                    ],
                    "created_at": db_incident.created_at,
                    "updated_at": db_incident.updated_at
                }
    except Exception as e:
        st.warning(f"Could not fetch incident details from database: {e}")
        return None
    return None


def get_security_guidance(incident: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Generate specific security guidance based on incident characteristics.

    Args:
        incident: Dictionary containing incident details

    Returns:
        Dictionary with 'do' and 'don't' lists
    """
    do_actions = []
    dont_actions = []

    # Determine primary entity type
    entity_types = incident.get("entities", [])
    primary_entity_type = "unknown"
    if entity_types:
        # Count entity types
        type_counts = {}
        for ent in entity_types:
            ent_type = ent.get("type", "unknown")
            type_counts[ent_type] = type_counts.get(ent_type, 0) + 1
        primary_entity_type = max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else "unknown"

    # Get confidence level
    confidence = incident.get("confidence_score", 0.0)
    confidence_level = "high" if confidence >= 0.7 else "medium" if confidence >= 0.4 else "low"

    # Get techniques
    techniques = incident.get("techniques", [])

    # Base guidance on entity type
    if primary_entity_type == "user":
        do_actions = [
            "Reset the user's password immediately",
            "Enable multi-factor authentication (MFA) for the user",
            "Review recent login locations and times for suspicious activity",
            "Check for any unauthorized access to sensitive data",
            "Monitor the user account for further anomalous behavior"
        ]
        dont_actions = [
            "Ignore the alert assuming it's a false positive",
            "Allow the user to continue using compromised credentials",
            "Delay action pending further investigation without interim protections",
            "Share password reset details via unsecured channels"
        ]
    elif primary_entity_type == "host":
        do_actions = [
            "Isolate the affected host from the network immediately",
            "Run a full antivirus and anti-malware scan",
            "Check for unauthorized software or scheduled tasks",
            "Review system logs for signs of lateral movement",
            "Collect forensic evidence for potential legal proceedings"
        ]
        dont_actions = [
            "Leave the host connected to the production network",
            "Allow users to continue using the host normally",
            "Power off the host without preserving volatile memory",
            "Attempt to clean the host without proper forensic procedures"
        ]
    elif primary_entity_type == "ip":
        do_actions = [
            "Block the IP address at the firewall perimeter",
            "Review traffic logs for data exfiltration patterns",
            "Check internal systems for communication with this IP",
            "Investigate if the IP is associated with known threat actors",
            "Monitor for alternative IP addresses used by the same threat actor"
        ]
        dont_actions = [
            "Assume the IP is spoofed without investigation",
            "Delay blocking pending further confirmation",
            "Share blocking details publicly that could alert attackers",
            "Overlook internal systems that may have initiated contact"
        ]
    elif primary_entity_type == "cloud_role":
        do_actions = [
            "Revoke the assumed cloud role/session immediately",
            "Rotate cloud credentials and review access logs",
            "Audit cloud role usage and permissions for principle of least privilege",
            "Check for any unauthorized data access or exfiltration",
            "Implement stricter conditional access policies for cloud resources"
        ]
        dont_actions = [
            "Assume the role assumption was legitimate without verification",
            "Delay revocation pending completion of other tasks",
            "Overlook other cloud roles that may have been compromised",
            "Fail to notify relevant cloud service provider of potential compromise"
        ]
    else:
        # Generic guidance
        do_actions = [
            "Isolate affected systems or accounts pending investigation",
            "Collect and preserve relevant logs and evidence",
            "Notify appropriate incident response team members",
            "Document all findings and actions taken",
            "Review and update security monitoring rules based on findings"
        ]
        dont_actions = [
            "Assume the incident is isolated without checking for related activity",
            "Delay notification to avoid panic or embarrassment",
            "Overlook potential regulatory or compliance reporting requirements",
            "Fail to conduct a lessons-learned session after resolution"
        ]

    # Adjust based on confidence level
    if confidence_level == "low":
        do_actions.insert(0, "Gather additional evidence before taking disruptive actions")
        dont_actions.append("Take drastic actions based solely on low-confidence alerts")
    elif confidence_level == "high":
        do_actions.insert(0, "Take immediate action based on high-confidence correlation")
        dont_actions.append("Wait for additional confirmation when confidence is high")

    # Add technique-specific guidance
    if any("T1078" in t for t in techniques):  # Valid Accounts
        do_actions.append("Review all active user sessions and consider forced re-authentication")
        dont_actions.append("Overlook service accounts or admin accounts in review")
    if any("T1110" in t for t in techniques):  # Brute Force
        do_actions.append("Implement account lockout policies and CAPTCHA where appropriate")
        dont_actions.append("Rely solely on password complexity without rate limiting")
    if any("T1041" in t for t in techniques):  # Exfiltration Over Command and Control
        do_actions.append("Monitor for unusual outbound traffic patterns and data transfers")
        dont_actions.append("Allow large data transfers without inspection or approval")

    return {
        "do": do_actions[:5],  # Limit to top 5
        "dont": dont_actions[:5]  # Limit to top 5
    }


def get_historical_similarity(incident_id: str) -> List[Dict[str, Any]]:
    """
    Find similar historical incidents from the database.

    Args:
        incident_id: Current incident ID to find similarities for

    Returns:
        List of similar historical incidents (empty list if storage not available or error)
    """
    if not STORAGE_AVAILABLE:
        return []

    try:
        with get_db_context() as db:
            incident_repo = IncidentRepository()
            # For now, we'll get recent incidents and do simple matching
            # In a full implementation, we would use more sophisticated similarity metrics
            recent_incidents = incident_repo.get_recent_incidents(db, limit=50)

            # Get current incident details for comparison
            current_incident = incident_repo.get_incident_by_id(db, incident_id)
            if not current_incident:
                return []

            similar = []
            current_techniques = set()
            if hasattr(current_incident, 'attack_techniques'):
                current_techniques = set(current_incident.attack_techniques)
            current_entities = set()
            if hasattr(current_incident, 'participating_entities'):
                for entity_type, values in current_incident.participating_entities.items():
                    for value in values:
                        current_entities.add((entity_type, value))

            for inc in recent_incidents:
                if inc.incident_id == incident_id:
                    continue  # Skip current incident

                # Simple similarity based on shared techniques or entities
                inc_techniques = set()
                if hasattr(inc, 'attack_techniques'):
                    inc_techniques = set(inc.attack_techniques)
                inc_entities = set()
                if hasattr(inc, 'participating_entities'):
                    for entity_type, values in inc.participating_entities.items():
                        for value in values:
                            inc_entities.add((entity_type, value))

                technique_similarity = len(current_techniques & inc_techniques) > 0
                entity_similarity = len(current_entities & inc_entities) > 0

                if technique_similarity or entity_similarity:
                    similar.append({
                        "incident_id": inc.incident_id,
                        "confidence_score": inc.confidence_score,
                        "time_range_start": inc.time_range_start,
                        "time_range_end": inc.time_range_end,
                        "recommended_action": inc.recommended_action,
                        "similarity_basis": "shared techniques" if technique_similarity else "shared entities"
                    })

            return similar[:3]  # Return top 3 most recent similar incidents
    except Exception as e:
        # In case of error, return empty list to avoid breaking the UI
        return []


def main() -> None:
    st.set_page_config(page_title="SOC Causal Correlation", layout="wide")
    st.title("Causal SOC Alert Correlation")
    st.caption("Paste timestamped alerts to group related activity, identify a likely root cause, and get a scoped response recommendation.")

    # Show database status
    if STORAGE_AVAILABLE:
        try:
            with get_db_context() as db:
                # Simple query to test connection
                from sqlalchemy import text
                db.execute(text("SELECT 1"))
            st.success("✅ Connected to PostgreSQL database for persistent storage and historical analysis")
        except Exception as e:
            st.warning(f"⚠️ Database connection failed: {e}. Running in memory-only mode.")
    else:
        st.info("ℹ️ Running in memory-only mode. Database storage not available.")

    raw_text = st.text_area("Security alerts", value=SAMPLE_ALERTS, height=220)
    left, middle, right = st.columns(3)
    with left:
        time_window = st.slider("Correlation window (minutes)", 5, 240, 30)
    with middle:
        min_alerts = st.number_input("Minimum alerts per incident", 1, 20, 2)
    with right:
        st.write("")
        analyze = st.button("Analyze alerts", type="primary", use_container_width=True)

    if not analyze:
        return

    alerts = alerts_from_text(raw_text)
    if not alerts:
        st.warning("No timestamped alert lines were found. Add one alert per line.")
        return

    result = analyze_alerts(alerts, time_window * 60, int(min_alerts))
    incidents = result["incidents"]
    st.subheader("Results")
    first, second, third = st.columns(3)
    first.metric("Input alerts", len(alerts))
    second.metric("Correlated incidents", len(incidents))
    third.metric("Compression", f"{len(alerts) / len(incidents):.1f}×" if incidents else "—")

    if not incidents:
        st.info("No cluster met the selected minimum. Reduce the minimum alert count or widen the time window.")
        return

    renderer = IncidentGraphRenderer(height="520px")
    for incident, summary, cluster in zip(incidents, result["summaries"], result["clusters"]):
        with st.expander(f"{incident.incident_id} — {len(incident.alert_ids)} alerts", expanded=True):
            # Get detailed incident information from database if available
            db_incident_details = get_db_incident_details(incident.incident_id)

            # Use database details if available, otherwise fall back to incident object
            incident_data = db_incident_details if db_incident_details else {
                "incident_id": incident.incident_id,
                "root_cause_alert_id": incident.root_cause_alert_id,
                "confidence_score": incident.confidence_score,
                "recommended_action": incident.recommended_action,
                "hypothesis": incident.hypothesis,
                "time_range_start": incident.time_range.get("start"),
                "time_range_end": incident.time_range.get("end"),
                "alert_ids": incident.alert_ids,
                "techniques": incident.attack_techniques,
                "entities": [
                    {"type": k, "value": v}
                    for k, vlist in incident.participating_entities.items()
                    for v in vlist
                ]
            }

            # Get security guidance
            security_guidance = get_security_guidance(incident_data)

            # Get historical similar incidents
            similar_incidents = get_historical_similarity(incident.incident_id)

            # Display metrics
            a, b, c = st.columns(3)
            a.metric("Confidence", f"{incident_data['confidence_score']:.0%}")
            b.markdown(f"**Likely root cause**  \n{incident_data['root_cause_alert_id'] or 'Unknown'}")
            c.markdown(f"**Recommended response**  \n{incident_data['recommended_action']}")

            # Display techniques
            st.markdown(f"**Techniques:** {', '.join(incident_data['techniques']) or 'Not identified'}")

            # Display alert details in a table
            st.dataframe(summary["alerts"], width='stretch', hide_index=True)

            # Display historical similarity if available
            if similar_incidents:
                st.markdown("### 🔍 Historical Similarity")
                st.info(f"Found {len(similar_incidents)} similar historical incident(s)")
                for sim in similar_incidents:
                    st.markdown(f"- **Incident {sim['incident_id']}** (confidence: {sim['confidence_score']:.0%}, {sim['similarity_basis']})")
                    if st.button(f"View details for {sim['incident_id']}", key=f"view_{sim['incident_id']}"):
                        # In a real app, we might navigate to a detailed view or show a modal
                        st.info(f"Would show detailed view for incident {sim['incident_id']}")

            # Display security guidance
            st.markdown("### 🛡️ Security Guidance")
            guidance_col1, guidance_col2 = st.columns(2)

            with guidance_col1:
                st.markdown("**✅ What to do**")
                for action in security_guidance["do"]:
                    st.markdown(f"• {action}")

            with guidance_col2:
                st.markdown("**❌ What not to do**")
                for action in security_guidance["dont"]:
                    st.markdown(f"• {action}")

            # Render the incident graph
            graph_html = renderer.render_incident_graph(
                result["graph"],
                incident_nodes=cluster,
                highlight_root_cause=incident.root_cause_alert_id,
            )
            if graph_html.lstrip().startswith("{"):
                st.json(graph_html)
            else:
                components.html(graph_html, height=540, scrolling=True)


if __name__ == "__main__":
    main()