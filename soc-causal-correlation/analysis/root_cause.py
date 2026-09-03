"""
Root cause identification: scoring based on in-degree, recency, technique-stage weighting
"""

import networkx as nx
from typing import List, Dict, Any, Tuple, Optional
try:
    # Try relative imports (when used as package)
    from ..schema import Alert, Incident
    from ..graph.clustering import summarize_incident
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Alert, Incident
    from graph.clustering import summarize_incident
import math

def identify_root_cause(G: nx.Graph, incident_nodes: set) -> Tuple[Optional[str], Dict[str, float]]:
    """
    Identify the root cause alert within an incident using multiple scoring factors.

    Args:
        G: The full alert-entity graph
        incident_nodes: Set of node IDs belonging to the incident

    Returns:
        Tuple of (root_cause_alert_id, scores_dict) where scores_dict contains
        Individual factor scores for each alert
    """
    # Get alert nodes in the incident
    alert_nodes = [node for node in incident_nodes if node.startswith("alert_")]

    if not alert_nodes:
        return None, {}

    if len(alert_nodes) == 1:
        # Only one alert, it's the root cause by default
        alert_id = G.nodes[alert_nodes[0]].get('alert_id')
        return alert_id, {alert_id: 1.0}

    # Calculate various scoring factors
    scores = {}

    # 1. Temporal scoring (earlier alerts get higher scores)
    temporal_scores = _calculate_temporal_scores(G, alert_nodes)

    # 2. In-degree scoring (alerts with fewer incoming edges are more likely root causes)
    indegree_scores = _calculate_indegree_scores(G, alert_nodes)

    # 3. Technique stage weighting (earlier attack stages get higher scores)
    technique_scores = _calculate_technique_stage_scores(G, alert_nodes)

    # 4. Entity centrality (alerts connected to fewer entities might be more primitive)
    entity_scores = _calculate_entity_centrality_scores(G, alert_nodes)

    # Combine scores with weights
    weights = {
        'temporal': 0.3,
        'indegree': 0.3,
        'technique': 0.25,
        'entity': 0.15
    }

    for alert_node in alert_nodes:
        alert_id = G.nodes[alert_node].get('alert_id')
        scores[alert_id] = (
            weights['temporal'] * temporal_scores.get(alert_node, 0.0) +
            weights['indegree'] * indegree_scores.get(alert_node, 0.0) +
            weights['technique'] * technique_scores.get(alert_node, 0.0) +
            weights['entity'] * entity_scores.get(alert_node, 0.0)
        )

    # Find alert with highest score
    if scores:
        root_cause_alert_id = max(scores, key=scores.get)
        return root_cause_alert_id, scores
    else:
        # Fallback: return first alert
        first_alert_id = G.nodes[alert_nodes[0]].get('alert_id')
        return first_alert_id, {first_alert_id: 1.0}

def _calculate_temporal_scores(G: nx.Graph, alert_nodes: List[str]) -> Dict[str, float]:
    """Calculate scores based on timestamp (earlier = higher score)"""
    timestamps = {}
    valid_alerts = []

    for node in alert_nodes:
        node_data = G.nodes[node]
        timestamp_str = node_data.get('timestamp')
        if timestamp_str:
            try:
                from datetime import datetime
                # Handle various timestamp formats
                dt = timestamp_str if isinstance(timestamp_str, datetime) else datetime.fromisoformat(
                    str(timestamp_str).replace(' ', 'T').replace('Z', '+00:00')
                )
                timestamps[node] = dt
                valid_alerts.append(node)
            except:
                pass

    if not valid_alerts:
        # If no valid timestamps, return equal scores
        return {node: 1.0/len(alert_nodes) for node in alert_nodes}

    # Find earliest and latest timestamps
    earliest = min(timestamps.values())
    latest = max(timestamps.values())
    time_span = (latest - earliest).total_seconds()

    scores = {}
    for node in alert_nodes:
        if node in timestamps:
            # Earlier alerts get higher scores
            time_diff = (timestamps[node] - earliest).total_seconds()
            if time_span > 0:
                # Normalize to 0-1 range, where earlier = higher score
                scores[node] = 1.0 - (time_diff / time_span)
            else:
                scores[node] = 1.0
        else:
            # No timestamp available
            scores[node] = 0.5

    return scores

def _calculate_indegree_scores(G: nx.Graph, alert_nodes: List[str]) -> Dict[str, float]:
    """Calculate scores based on in-degree (lower in-degree = higher score)"""
    # Calculate in-degree considering only edges between alerts
    alert_subgraph = G.subgraph(alert_nodes)

    indegrees = dict(alert_subgraph.degree())

    if not indegrees:
        return {node: 1.0/len(alert_nodes) for node in alert_nodes}

    max_indegree = max(indegrees.values()) if indegrees.values() else 1

    scores = {}
    for node in alert_nodes:
        indegree = indegrees.get(node, 0)
        # Lower in-degree = higher score
        if max_indegree > 0:
            scores[node] = 1.0 - (indegree / max_indegree)
        else:
            scores[node] = 1.0

    return scores

def _calculate_technique_stage_scores(G: nx.Graph, alert_nodes: List[str]) -> Dict[str, float]:
    """Calculate scores based on MITRE technique stage (earlier in attack chain = higher score)"""
    # Define technique stages (simplified MITRE ATT&CK framework)
    technique_stages = {
        # Reconnaissance
        'T1595': 1, 'T1596': 1, 'T1597': 1, 'T1598': 1, 'T1599': 1, 'T1600': 1,
        # Resource Development
        'T1583': 2, 'T1584': 2, 'T1585': 2, 'T1586': 2, 'T1587': 2, 'T1588': 2,
        # Initial Access
        'T1078': 3, 'T1190': 3, 'T1133': 3, 'T1195': 3, 'T1199': 3, 'T1190': 3,
        # Execution
        'T1059': 4, 'T1059.001': 4, 'T1059.002': 4, 'T1059.003': 4, 'T1059.004': 4, 'T1059.005': 4,
        # Persistence
        'T1505': 5, 'T1505.001': 5, 'T1505.002': 5, 'T1547': 5, 'T1547.001': 5, 'T1547.002': 5,
        # Privilege Escalation
        'T1068': 6, 'T1055': 6, 'T1055.001': 6, 'T1055.002': 6, 'T1055.003': 6,
        # Defense Evasion
        'T1070': 7, 'T1070.001': 7, 'T1070.002': 7, 'T1070.003': 7, 'T1070.004': 7, 'T1070.005': 7,
        # Credential Access
        'T1110': 8, 'T1110.001': 8, 'T1110.002': 8, 'T1110.003': 8, 'T1110.004': 8,
        # Discovery
        'T1082': 9, 'T1083': 9, 'T1087': 9, 'T1087.001': 9, 'T1087.002': 9,
        # Lateral Movement
        'T1021': 10, 'T1021.001': 10, 'T1021.002': 10, 'T1021.003': 10, 'T1021.004': 10,
        # Collection
        'T1114': 11, 'T1114.001': 11, 'T1114.002': 11, 'T1115': 11,
        # Command and Control
        'T1071': 12, 'T1071.001': 12, 'T1071.002': 12, 'T1071.003': 12, 'T1071.004': 12,
        # Exfiltration
        'T1041': 13, 'T1041.001': 13, 'T1041.002': 13, 'T1041.003': 13,
        # Impact
        'T1486': 14, 'T1486.001': 14, 'T1486.002': 14, 'T1489': 14, 'T1490': 14, 'T1491': 14
    }

    # Default stage for unknown techniques
    default_stage = 7
    max_stage = max(technique_stages.values()) if technique_stages else 1

    scores = {}
    for node in alert_nodes:
        node_data = G.nodes[node]
        technique = node_data.get('mitre_technique')

        if technique and technique in technique_stages:
            stage = technique_stages[technique]
        else:
            stage = default_stage

        # Earlier stages get higher scores (invert the scale)
        if max_stage > 1:
            scores[node] = 1.0 - ((stage - 1) / (max_stage - 1))
        else:
            scores[node] = 1.0

    return scores

def _calculate_entity_centrality_scores(G: nx.Graph, alert_nodes: List[str]) -> Dict[str, float]:
    """Calculate scores based on entity connectivity (fewer entities = higher score)"""
    scores = {}

    for node in alert_nodes:
        # Count entity neighbors
        entity_neighbors = 0
        for neighbor in G.neighbors(node):
            neighbor_data = G.nodes[neighbor]
            if neighbor_data.get('type') == 'entity':
                entity_neighbors += 1

        # Fewer entities = higher score (more primitive/compromised entity)
        # Use inverse, but cap to avoid division by zero
        scores[node] = 1.0 / (1.0 + entity_neighbors)

    # Normalize scores
    max_score = max(scores.values()) if scores.values() else 1.0
    if max_score > 0:
        scores = {node: score/max_score for node, score in scores.items()}

    return scores

def calculate_incident_confidence(G: nx.Graph, incident_nodes: set) -> float:
    """
    Calculate confidence score for an incident based on graph connectivity and consistency.

    Args:
        G: The full alert-entity graph
        incident_nodes: Set of node IDs belonging to the incident

    Returns:
        Confidence score between 0.0 and 1.0
    """
    subgraph = G.subgraph(incident_nodes).copy()

    if subgraph.number_of_nodes() < 2:
        return 0.0

    # Factor 1: Graph density (how well connected is the incident?)
    density = nx.density(subgraph) if subgraph.number_of_nodes() > 1 else 0.0

    # Factor 2: Alert-to-entity ratio (balanced incidents have good entity coverage)
    alert_nodes = [n for n in incident_nodes if n.startswith("alert_")]
    entity_nodes = [n for n in incident_nodes if not n.startswith("alert_")]

    if len(alert_nodes) == 0:
        entity_ratio = 0.0
    else:
        entity_ratio = min(1.0, len(entity_nodes) / len(alert_nodes))

    # Factor 3: Temporal cohesion (how close together in time are the alerts?)
    temporal_cohesion = _calculate_temporal_cohesion(subgraph, alert_nodes)

    # Factor 4: Technique consistency (are techniques related?)
    technique_consistency = _calculate_technique_consistency(subgraph, alert_nodes)

    # Weighted combination
    confidence = (
        0.3 * density +
        0.25 * entity_ratio +
        0.25 * temporal_cohesion +
        0.2 * technique_consistency
    )

    return min(1.0, max(0.0, confidence))

def _calculate_temporal_cohesion(subgraph: nx.Graph, alert_nodes: List[str]) -> float:
    """Calculate how tightly clustered the alerts are in time"""
    timestamps = []

    for node in alert_nodes:
        node_data = subgraph.nodes[node]
        timestamp_str = node_data.get('timestamp')
        if timestamp_str:
            try:
                from datetime import datetime
                dt = timestamp_str if isinstance(timestamp_str, datetime) else datetime.fromisoformat(
                    str(timestamp_str).replace(' ', 'T').replace('Z', '+00:00')
                )
                timestamps.append(dt)
            except:
                pass

    if len(timestamps) < 2:
        return 0.5  # Not enough data

    # Calculate time span in hours
    time_span_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600

    # Convert to score: shorter time span = higher cohesion
    # Assuming 24 hours is the threshold for low cohesion
    cohesion = max(0.0, 1.0 - (time_span_hours / 24.0))
    return min(1.0, cohesion)

def _calculate_technique_consistency(subgraph: nx.Graph, alert_nodes: List[str]) -> float:
    """Calculate how consistent the MITRE techniques are (related tactics)"""
    techniques = []

    for node in alert_nodes:
        node_data = subgraph.nodes[node]
        technique = node_data.get('mitre_technique')
        if technique:
            techniques.append(technique)

    if len(techniques) < 2:
        return 0.5  # Not enough data

    # Group techniques by tactic (first part of MITRE ID)
    tactic_map = {
        'T1595': 'reconnaissance', 'T1596': 'reconnaissance', 'T1597': 'reconnaissance',
        'T1598': 'reconnaissance', 'T1599': 'reconnaissance', 'T1600': 'reconnaissance',
        'T1583': 'resource-development', 'T1584': 'resource-development',
        'T1585': 'resource-development', 'T1586': 'resource-development',
        'T1587': 'resource-development', 'T1588': 'resource-development',
        'T1078': 'initial-access', 'T1190': 'initial-access', 'T1133': 'initial-access',
        'T1195': 'initial-access', 'T1199': 'initial-access',
        'T1059': 'execution', 'T1059.001': 'execution', 'T1059.002': 'execution',
        'T1505': 'persistence', 'T1505.001': 'persistence', 'T1505.002': 5,  # Note: duplicate key; later overwritten by 5
        'T1547': 'persistence', 'T1547.001': 'persistence', 'T1547.002': 'persistence',
        'T1068': 'privilege-escalation', 'T1055': 'privilege-escalation',
        'T1070': 'defense-evasion', 'T1070.001': 'defense-evasion',
        'T1110': 'credential-access', 'T1110.001': 'credential-access',
        'T1082': 'discovery', 'T1083': 'discovery', 'T1087': 'discovery',
        'T1021': 'lateral-movement', 'T1021.001': 'lateral-movement',
        'T1114': 'collection', 'T1114.001': 'collection',
        'T1071': 'command-and-control', 'T1071.001': 'command-and-control',
        'T1041': 'exfiltration', 'T1041.001': 'exfiltration',
        'T1486': 'impact', 'T1486.001': 'impact'
    }

    tactics = []
    for tech in techniques:
        # Extract base technique ID (e.g., T1059.001 -> T1059)
        base_tech = tech.split('.')[0]
        tactic = tactic_map.get(base_tech, 'unknown')
        tactics.append(tactic)

    if not tactics:
        return 0.5

    # Calculate consistency: percentage of alerts in most common tactic
    from collections import Counter
    tactic_counts = Counter(tactics)
    most_common_count = tactic_counts.most_common(1)[0][1]
    consistency = most_common_count / len(tactics)

    return consistency
