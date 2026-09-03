"""One callable, offline-capable end-to-end alert-correlation workflow."""

from collections import defaultdict
from typing import Any, Dict, List, Tuple, Set
import itertools

import networkx as nx

from analysis.response_recommender import recommend_response
from analysis.root_cause import calculate_incident_confidence, identify_root_cause
from graph.build_graph import add_technique_based_edges, add_temporal_edges, build_alert_entity_graph
from graph.clustering import filter_incidents_by_size, summarize_incident
from graph.times_pruning import add_entity_decay_weights, prune_entity_edges_by_time
from ingestion.heuristic_normalizer import normalize_alert_locally
from ingestion.text_input import split_into_alert_chunks
from schema import Alert, Incident


def _filter_low_weight_edges(G: nx.Graph, weight_threshold: float = 0.5) -> Tuple[nx.Graph, List[Tuple[Any, Any, str]]]:
    """Remove edges with weight below threshold to split weakly connected components.
    
    Args:
        G: NetworkX graph with edge 'weight' attribute
        weight_threshold: Minimum weight to keep an edge (default 0.5)
    
    Returns:
        Tuple of (filtered_graph, list_of_removed_edges_with_reason)
        where each removed edge is (u, v, reason) and reason is a string.
    """
    G_filtered = G.copy()
    removed = []
    for u, v, d in list(G_filtered.edges(data=True)):
        w = d.get('weight', 1.0)
        if w < weight_threshold:
            G_filtered.remove_edge(u, v)
            removed.append((u, v, f'weight_below_threshold:{w:.3f}<{weight_threshold}'))
    return G_filtered, removed


def alerts_from_text(raw_text: str) -> List[Alert]:
    """Split pasted text and normalize it locally, with no credentials required."""
    return [
        normalize_alert_locally(chunk["raw_text"], f"alert_{index + 1:03d}")
        for index, chunk in enumerate(split_into_alert_chunks(raw_text))
    ]


def _alert_connected_components(G: nx.Graph) -> List[Set[str]]:
    """
    Find connected components considering only direct alert-alert edges.
    Two alerts are considered connected if there is an edge between them in G
    where both nodes are alerts (regardless of weight, as we already filtered low weights).
    Returns a list of sets, each set containing alert node IDs that belong to one component.
    """
    # Get alert nodes
    alert_nodes = {n for n, d in G.nodes(data=True) if d.get('type') == 'alert'}
    if not alert_nodes:
        return []

    # Build alert-only graph H with edges only between alerts
    H = nx.Graph()
    H.add_nodes_from(alert_nodes)

    for u, v, d in G.edges(data=True):
        if u in alert_nodes and v in alert_nodes:
            H.add_edge(u, v)

    # Find connected components in H (alert-only)
    components_alerts = [set(comp) for comp in nx.connected_components(H)]
    return components_alerts


def analyze_alerts(
    alerts: List[Alert],
    time_window_seconds: int = 1800,
    min_alerts: int = 2,
    weight_threshold: float = 0.9
) -> Dict[str, Any]:
    """Correlate alerts and return graph, incident objects, display summaries, and split subgraphs.
    
    Args:
        alerts: List of Alert objects
        time_window_seconds: Time window in seconds for temporal edges
        min_alerts: Minimum number of alerts required for an incident
        weight_threshold: Minimum edge weight to retain for clustering (default 0.5)
    
    Returns:
        Dictionary containing:
        - graph: filtered graph after all processing and weight thresholding
        - subgraphs: list of NetworkX subgraphs, one per incident cluster
        - clusters: list of node sets (same length as subgraphs) – includes alerts + their entities
        - incidents: list of Incident objects
        - summaries: list of dict summaries for each incident
        - removed_edges: list of edges removed by weight filtering with reason
    """
    graph = build_alert_entity_graph(alerts)
    graph = add_temporal_edges(graph, alerts, time_window_seconds)
    graph = add_technique_based_edges(graph, alerts)
    graph = add_entity_decay_weights(graph)
    graph = prune_entity_edges_by_time(graph)
    # Remove weak edges to allow splitting into multiple components
    graph, removed_edges = _filter_low_weight_edges(graph, weight_threshold)

    # Find alert-only connected components (based on direct alert-alert edges)
    alert_components = _alert_connected_components(graph)
    # Filter by min_alerts
    alert_components = [comp for comp in alert_components if len(comp) >= min_alerts]

    incidents: List[Incident] = []
    summaries: List[Dict[str, Any]] = []
    subgraphs: List[nx.Graph] = []
    clusters: List[Set[str]] = []  # will include alerts + entities

    for alert_comp in alert_components:
        # Determine entity nodes that are neighbors of any alert in this component
        entity_nodes = set()
        for a in alert_comp:
            for nbr in graph.neighbors(a):
                if graph.nodes[nbr].get('type') == 'entity':
                    entity_nodes.add(nbr)
        comp_nodes = alert_comp.union(entity_nodes)
        clusters.append(comp_nodes)

        subgraph = graph.subgraph(comp_nodes).copy()
        subgraphs.append(subgraph)

        summary = summarize_incident(graph, comp_nodes)
        root_cause, scores = identify_root_cause(graph, comp_nodes)
        confidence = calculate_incident_confidence(graph, comp_nodes)
        participants: Dict[str, List[str]] = defaultdict(list)
        for node in comp_nodes:
            data = graph.nodes[node]
            if data.get("type") == "entity":
                participants[data.get("entity_type", "unknown")].append(data.get("entity_value", ""))
        time_range = {"start": None, "end": None}
        timestamps = [item["timestamp"] for item in summary["alerts"] if item["timestamp"]]
        if timestamps:
            time_range = {"start": min(timestamps), "end": max(timestamps)}
        incident = Incident(
            incident_id=summary["incident_id"],
            alert_ids=[item["alert_id"] for item in summary["alerts"]],
            root_cause_alert_id=root_cause,
            participating_entities=dict(participants),
            time_range=time_range,
            attack_techniques=summary["techniques"],
            confidence_score=confidence,
        )
        incident.recommended_action = recommend_response(incident, summary)
        summary.update({
            "root_cause_alert_id": root_cause,
            "root_cause_scores": scores,
            "confidence_score": confidence,
            "recommended_action": incident.recommended_action,
        })
        incidents.append(incident)
        summaries.append(summary)

    return {
        "graph": graph,
        "subgraphs": subgraphs,
        "clusters": clusters,
        "incidents": incidents,
        "summaries": summaries,
        "removed_edges": removed_edges
    }
