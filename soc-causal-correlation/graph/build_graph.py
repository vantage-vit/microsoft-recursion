"""
Build graph: builds bipartite alert<->entity networkx graph
"""

import networkx as nx
from typing import List, Dict, Any
try:
    # Try relative imports (when used as package)
    from ..schema import Alert
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Alert
import hashlib

def build_alert_entity_graph(alerts: List[Alert]) -> nx.Graph:
    """
    Build a bipartite graph connecting alerts to entities they mention.

    Args:
        alerts: List of Alert objects

    Returns:
        NetworkX graph where nodes are alerts and entities, edges represent
        alert-entity relationships
    """
    G = nx.Graph()

    # Add alert nodes
    for alert in alerts:
        alert_node_id = f"alert_{alert.alert_id}"
        G.add_node(alert_node_id,
                  type='alert',
                  alert_id=alert.alert_id,
                  timestamp=alert.timestamp,
                  source_product=alert.source_product,
                  alert_type=alert.alert_type,
                  severity=alert.severity,
                  raw_text=alert.raw_text)

    # Add entity nodes and edges
    for alert in alerts:
        alert_node_id = f"alert_{alert.alert_id}"

        # Process each entity type in the alert
        # Convert Pydantic model to dict to iterate over fields
        entities_dict = alert.entities.model_dump()
        for entity_type, entity_value in entities_dict.items():
            if not entity_value:  # Skip empty values
                continue

            # Create a unique entity node ID
            entity_node_id = f"entity_{entity_type}_{hashlib.md5(str(entity_value).encode()).hexdigest()[:8]}"

            # Add entity node if it doesn't exist
            if not G.has_node(entity_node_id):
                G.add_node(entity_node_id,
                          type='entity',
                          entity_type=entity_type,
                          entity_value=str(entity_value))

            # Add edge between alert and entity
            G.add_edge(alert_node_id, entity_node_id,
                      relationship='mentions',
                      weight=1.0)  # Can be weighted based on confidence

    return G

def add_temporal_edges(G: nx.Graph, alerts: List[Alert], time_window_seconds: int = 1800) -> nx.Graph:
    """
    Add temporal edges between alerts that occur within a time window.

    Args:
        G: Existing alert-entity graph
        alerts: List of Alert objects
        time_window_seconds: Time window in seconds for considering alerts related

    Returns:
        Graph with additional temporal edges
    """
    # Sort alerts by timestamp
    timed_alerts = []
    for alert in alerts:
        if alert.timestamp:
            try:
                # Parse timestamp (simple parsing for MVP)
                from datetime import datetime
                # Handle various formats
                ts_str = alert.timestamp.replace(' ', 'T')
                dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                timed_alerts.append((dt, alert))
            except:
                # Skip alerts with unparseable timestamps
                continue

    timed_alerts.sort(key=lambda x: x[0])

    # Add edges between alerts within time window
    for i, (time_i, alert_i) in enumerate(timed_alerts):
        for j, (time_j, alert_j) in enumerate(timed_alerts[i+1:], i+1):
            time_diff = abs((time_j - time_i).total_seconds())

            if time_diff <= time_window_seconds:
                alert_i_node = f"alert_{alert_i.alert_id}"
                alert_j_node = f"alert_{alert_j.alert_id}"

                # Only add edge if not already connected through entities
                if not G.has_edge(alert_i_node, alert_j_node):
                    # Weight based on temporal proximity (closer = higher weight)
                    weight = 1.0 - (time_diff / time_window_seconds)
                    G.add_edge(alert_i_node, alert_j_node,
                              relationship='temporal_proximity',
                              weight=max(0.1, weight),  # Minimum weight of 0.1
                              time_diff_seconds=time_diff)
            else:
                # Since sorted, break if we're beyond the window
                break

    return G

def add_technique_based_edges(G: nx.Graph, alerts: List[Alert]) -> nx.Graph:
    """
    Add edges between alerts that share similar MITRE techniques or attack patterns.

    Args:
        G: Existing graph
        alerts: List of Alert objects

    Returns:
        Graph with technique-based edges
    """
    # Group alerts by MITRE technique
    technique_to_alerts = {}
    for alert in alerts:
        if alert.mitre_technique:
            if alert.mitre_technique not in technique_to_alerts:
                technique_to_alerts[alert.mitre_technique] = []
            technique_to_alerts[alert.mitre_technique].append(alert)

    # Add edges between alerts sharing the same technique
    for technique, alert_list in technique_to_alerts.items():
        if len(alert_list) > 1:
            for i in range(len(alert_list)):
                for j in range(i+1, len(alert_list)):
                    alert_i = alert_list[i]
                    alert_j = alert_list[j]
                    alert_i_node = f"alert_{alert_i.alert_id}"
                    alert_j_node = f"alert_{alert_j.alert_id}"

                    if not G.has_edge(alert_i_node, alert_j_node):
                        G.add_edge(alert_i_node, alert_j_node,
                                  relationship='shared_technique',
                                  weight=0.8,  # High weight for shared technique
                                  mitre_technique=technique)

    return G

if __name__ == "__main__":
    # Test the graph building
    try:
        # Try relative imports first (when used as package)
        from ..ingestion.text_input import split_into_alert_chunks
        from ..ingestion.llm_normalizer import LLMPromptNormalizer
        from ..ingestion.validators import validate_and_normalize_alert
    except ImportError:
        # Fall back to absolute imports (when run directly)
        from ingestion.text_input import split_into_alert_chunks
        from ingestion.llm_normalizer import LLMPromptNormalizer
        from ingestion.validators import validate_and_normalize_alert

    sample_text = """
    2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
    2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
    2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
    """

    # This would normally use the LLM, but for testing we'll create mock alerts
    try:
        from ..schema import Alert
    except ImportError:
        from schema import Alert

    mock_alerts = [
        Alert(
            alert_id="alert_001",
            timestamp="2023-01-15T09:14:02",
            source_product="Identity Platform",
            alert_type="Failed logins",
            severity="medium",
            entities={"user": "j.suresh@acmecorp.com"},
            raw_text="2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com",
            mitre_technique="T1110"
        ),
        Alert(
            alert_id="alert_002",
            timestamp="2023-01-15T09:16:40",
            source_product="Identity Platform",
            alert_type="Successful login",
            severity="medium",
            entities={"user": "j.suresh@acmecorp.com"},
            raw_text="2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com",
            mitre_technique="T1078"
        ),
        Alert(
            alert_id="alert_003",
            timestamp="2023-01-15T09:18:12",
            source_product="Endpoint (EDR)",
            alert_type="PowerShell activity",
            severity="high",
            entities={"host": "DESKTOP-7QK41", "process": "powershell.exe"},
            raw_text="2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41",
            mitre_technique="T1059.001"
        )
    ]

    # Build graph
    G = build_alert_entity_graph(mock_alerts)
    G = add_temporal_edges(G, mock_alerts, time_window_seconds=300)  # 5 minute window
    G = add_technique_based_edges(G, mock_alerts)

    print(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
    print("Nodes:", list(G.nodes(data=True))[:3])  # Show first 3 nodes
    print("Edges:", list(G.edges(data=True))[:3])  # Show first 3 edges