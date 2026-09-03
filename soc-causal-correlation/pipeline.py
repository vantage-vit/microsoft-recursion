"""One callable, offline-capable end-to-end alert-correlation workflow."""

from collections import defaultdict
from typing import Any, Dict, List

from analysis.response_recommender import recommend_response
from analysis.root_cause import calculate_incident_confidence, identify_root_cause
from graph.build_graph import add_technique_based_edges, add_temporal_edges, build_alert_entity_graph
from graph.clustering import filter_incidents_by_size, find_incident_clusters, summarize_incident
from graph.times_pruning import add_entity_decay_weights, prune_entity_edges_by_time
from ingestion.heuristic_normalizer import normalize_alert_locally
from ingestion.text_input import split_into_alert_chunks
from schema import Alert, Incident


def alerts_from_text(raw_text: str) -> List[Alert]:
    """Split pasted text and normalize it locally, with no credentials required."""
    return [
        normalize_alert_locally(chunk["raw_text"], f"alert_{index + 1:03d}")
        for index, chunk in enumerate(split_into_alert_chunks(raw_text))
    ]


def analyze_alerts(
    alerts: List[Alert], time_window_seconds: int = 1800, min_alerts: int = 2
) -> Dict[str, Any]:
    """Correlate alerts and return graph, incident objects, and display summaries."""
    graph = build_alert_entity_graph(alerts)
    graph = add_temporal_edges(graph, alerts, time_window_seconds)
    graph = add_technique_based_edges(graph, alerts)
    graph = add_entity_decay_weights(graph)
    graph = prune_entity_edges_by_time(graph)

    clusters = filter_incidents_by_size(
        find_incident_clusters(graph), min_alerts=min_alerts
    )
    incidents: List[Incident] = []
    summaries: List[Dict[str, Any]] = []
    for nodes in clusters:
        summary = summarize_incident(graph, nodes)
        root_cause, scores = identify_root_cause(graph, nodes)
        confidence = calculate_incident_confidence(graph, nodes)
        participants: Dict[str, List[str]] = defaultdict(list)
        for node in nodes:
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
    return {"graph": graph, "clusters": clusters, "incidents": incidents, "summaries": summaries}
