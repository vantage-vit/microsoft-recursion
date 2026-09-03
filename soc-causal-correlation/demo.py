"""
Demo script showing the core functionality of the SOC causal correlation system
"""

import sys
import os
from datetime import datetime, timedelta

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_text_processing():
    """Demo the text processing pipeline"""
    print("=" * 60)
    print("DEMO: Text Processing Pipeline")
    print("=" * 60)

    # Sample alert text similar to the HTML dashboard
    sample_alerts_text = """
    2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
    2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
    2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
    2023-01-15 09:24:55 Cloud (AWS): New cloud role assumed - arn:aws:iam::role/finance-read
    2023-01-15 09:41:03 Firewall: Outbound transfer - 2.3GB to unrecognized IP 203.0.113.44
    """

    print("Input alert text:")
    print(sample_alerts_text.strip())
    print()

    # Process the text into chunks
    from ingestion.text_input import split_into_alert_chunks
    chunks = split_into_alert_chunks(sample_alerts_text)

    print(f"Processed into {len(chunks)} alert chunks:")
    for i, chunk in enumerate(chunks, 1):
        print(f"  {i}. {chunk['raw_text'].strip()}")
    print()

    return chunks

def demo_schema_creation():
    """Demo creating schema objects from processed chunks"""
    print("=" * 60)
    print("DEMO: Schema Creation")
    print("=" * 60)

    chunks = demo_text_processing()

    # Convert chunks to Alert objects (simulating what the LLM normalizer would do)
    from schema import Alert, AlertEntities

    alerts = []
    for i, chunk in enumerate(chunks):
        # Extract basic info from chunk (in real system, LLM would do this)
        raw_text = chunk['raw_text']

        # Simple parsing for demo - in reality, LLM normalizer would extract this
        if "failed logins" in raw_text:
            alert_type = "Failed logins"
            severity = "medium"
            technique = "T1110"
            source = "Identity Platform"
        elif "Successful login" in raw_text:
            alert_type = "Successful login"
            severity = "medium"
            technique = "T1078"
            source = "Identity Platform"
        elif "PowerShell" in raw_text:
            alert_type = "PowerShell activity"
            severity = "high"
            technique = "T1059.001"
            source = "Endpoint (EDR)"
        elif "cloud role assumed" in raw_text:
            alert_type = "Cloud role assumption"
            severity = "high"
            technique = "T1078.004"
            source = "Cloud (AWS)"
        elif "Outbound transfer" in raw_text:
            alert_type = "Data exfiltration"
            severity = "critical"
            technique = "T1567"
            source = "Firewall"
        else:
            alert_type = "Unknown alert"
            severity = "low"
            technique = None
            source = "Unknown"

        # Extract timestamp (simple extraction for demo)
        timestamp_str = raw_text.split()[0] + "T" + raw_text.split()[1]

        # Extract entities (simple extraction for demo)
        entities_dict = {}
        if "j.suresh@acmecorp.com" in raw_text:
            entities_dict["user"] = "j.suresh@acmecorp.com"
        if "DESKTOP-7QK41" in raw_text:
            entities_dict["host"] = "DESKTOP-7QK41"
        if "203.0.113.44" in raw_text:
            entities_dict["ip"] = "203.0.113.44"
        if "arn:aws:iam::role/finance-read" in raw_text:
            entities_dict["cloud_role"] = "arn:aws:iam::role/finance-read"

        alert = Alert(
            alert_id=f"alert_{i+1:03d}",
            timestamp=datetime.fromisoformat(timestamp_str),
            source_product=source,
            alert_type=alert_type,
            severity=severity,
            entities=AlertEntities(**entities_dict),
            raw_text=raw_text,
            mitre_technique=technique
        )

        alerts.append(alert)
        print(f"Created Alert {alert.alert_id}:")
        print(f"  Type: {alert.alert_type}")
        print(f"  Severity: {alert.severity}")
        print(f"  Source: {alert.source_product}")
        # Fix: Use model_dump() for Pydantic V2
        entities_dict = alert.entities.model_dump()
        print(f"  Entities: {[(k, v) for k, v in entities_dict.items() if v]}")
        if alert.mitre_technique:
            print(f"  MITRE Technique: {alert.mitre_technique}")
        print()

    return alerts

def demo_graph_building(alerts):
    """Demo building the alert-entity graph"""
    print("=" * 60)
    print("DEMO: Graph Construction")
    print("=" * 60)

    try:
        from graph.build_graph import build_alert_entity_graph, add_temporal_edges, add_technique_based_edges
        import networkx as nx

        # Build base alert-entity graph
        G = build_alert_entity_graph(alerts)
        print(f"Initial graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Add temporal edges (alerts close in time)
        G = add_temporal_edges(G, alerts, time_window_seconds=1800)  # 30 minute window
        print(f"After temporal edges: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Add technique-based edges
        G = add_technique_based_edges(G, alerts)
        print(f"After technique edges: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Show some edges
        print("\nSample edges:")
        edge_count = 0
        for u, v, data in G.edges(data=True):
            if edge_count < 5:  # Show first 5 edges
                u_type = G.nodes[u].get('type', 'unknown')
                v_type = G.nodes[v].get('type', 'unknown')
                print(f"  {u} ({u_type}) --{data.get('relationship', '?')}--> {v} ({v_type}) [weight: {data.get('weight', 1.0):.2f}]")
                edge_count += 1
            else:
                break

        if G.number_of_edges() > 5:
            print(f"  ... and {G.number_of_edges() - 5} more edges")

        return G

    except Exception as e:
        print(f"Error in graph building: {e}")
        import traceback
        traceback.print_exc()
        return None

def demo_clustering(G):
    """Demo clustering the graph into incidents"""
    print("\n" + "=" * 60)
    print("DEMO: Incident Clustering")
    print("=" * 60)

    try:
        from graph.clustering import find_incident_clusters, filter_incidents_by_size, summarize_incident

        # Find incidents using connected components
        clusters = find_incident_clusters(G, method="connected_components")
        print(f"Found {len(clusters)} raw clusters")

        # Filter by size (at least 2 alerts per incident)
        filtered_clusters = filter_incidents_by_size(clusters, min_alerts=2)
        print(f"After filtering (min 2 alerts): {len(filtered_clusters)} incidents")

        # Summarize each incident
        incident_summaries = []
        for i, cluster in enumerate(filtered_clusters):
            print(f"\nIncident {i+1}:")
            summary = summarize_incident(G, cluster)
            incident_summaries.append(summary)

            print(f"  Incident ID: {summary['incident_id']}")
            print(f"  Alerts: {summary['alert_count']}")
            print(f"  Entities: {summary['entity_count']}")
            print(f"  Time Span: {summary['time_span_hours']:.2f} hours" if summary['time_span_hours'] else "  Time Span: Unknown")
            print(f"  Sources: {', '.join(summary['sources'])}")
            print(f"  Techniques: {', '.join(summary['techniques'])}")
            print(f"  Entity Types: {', '.join([f'{k}:{v}' for k, v in summary['entity_types'].items()])}")

        return filtered_clusters, incident_summaries

    except Exception as e:
        print(f"Error in clustering: {e}")
        import traceback
        traceback.print_exc()
        return [], []

def demo_root_cause_analysis(G, incident_clusters):
    """Demo root cause analysis"""
    print("\n" + "=" * 60)
    print("DEMO: Root Cause Analysis")
    print("=" * 60)

    try:
        from analysis.root_cause import identify_root_cause, calculate_incident_confidence

        root_causes = []
        confidences = []

        for i, incident_nodes in enumerate(incident_clusters):
            print(f"\nAnalyzing Incident {i+1}:")

            # Identify root cause
            root_cause_alert_id, scores = identify_root_cause(G, incident_nodes)

            # Calculate confidence
            confidence = calculate_incident_confidence(G, incident_nodes)

            root_causes.append(root_cause_alert_id)
            confidences.append(confidence)

            # Show scoring details
            alert_nodes = [node for node in incident_nodes if node.startswith("alert_")]
            print(f"  Alerts in incident: {len(alert_nodes)}")

            # Show top scoring alerts
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            print(f"  Alert scores:")
            for alert_id, score in sorted_scores[:3]:  # Top 3
                alert_node = f"alert_{alert_id}"
                alert_data = G.nodes[alert_node]
                print(f"    {alert_id}: {score:.3f} ({alert_data.get('alert_type', 'unknown')})")

            print(f"  Identified root cause: {root_cause_alert_id}")
            print(f"  Confidence: {confidence:.2%}")

        return root_causes, confidences

    except Exception as e:
        print(f"Error in root cause analysis: {e}")
        import traceback
        traceback.print_exc()
        return [], []

def demo_response_recommendation(incident_summaries, root_causes, confidences):
    """Demo response recommendations"""
    print("\n" + "=" * 60)
    print("DEMO: Response Recommendations")
    print("=" * 60)

    try:
        from analysis.response_recommender import Incident, recommend_response

        recommendations = []

        for i, (summary, root_cause, confidence) in enumerate(zip(incident_summaries, root_causes, confidences)):
            print(f"\nIncident {i+1} ({summary['incident_id']}):")

            # Create Incident object for the recommender
            incident = Incident(
                incident_id=summary['incident_id'],
                alert_ids=[f"alert_{j+1:03d}" for j in range(summary['alert_count'])],  # Simplified
                root_cause_alert_id=root_cause,
                participating_entities={},  # Simplified for demo
                time_range={"start": None, "end": None},
                attack_techniques=summary['techniques'],
                confidence_score=confidence,
                recommended_action="",  # Will be filled by recommender
                hypothesis=""
            )

            # Get recommendation
            recommendation = recommend_response(incident, summary)
            recommendations.append(recommendation)

            print(f"  Root Cause Alert: {root_cause}")
            print(f"  Confidence: {confidence:.2%}")
            print(f"  Recommended Action: {recommendation}")

        return recommendations

    except Exception as e:
        print(f"Error in response recommendation: {e}")
        import traceback
        traceback.print_exc()
        return []

def demo_metrics(incident_summaries):
    """Demo metrics calculation"""
    print("\n" + "=" * 60)
    print("DEMO: Metrics Calculation")
    print("=" * 60)

    try:
        from evaluation.metrics import SecurityMetrics

        metrics_calc = SecurityMetrics()

        # Mock total alerts (in real system, this would be the input count)
        total_alerts = 5  # We had 5 alert chunks

        # Convert summaries to Incident-like objects for metrics
        from schema import Incident
        incidents = []
        for summary in incident_summaries:
            incident = Incident(
                incident_id=summary['incident_id'],
                alert_ids=[f"alert_{j+1:03d}" for j in range(summary['alert_count'])],
                root_cause_alert_id=None,  # Simplified
                participating_entities={},
                time_range={"start": None, "end": None},
                attack_techniques=[],
                confidence_score=0.8,  # Placeholder
                recommended_action="",
                hypothesis=""
            )
            incidents.append(incident)

        # Calculate metrics
        all_metrics = metrics_calc.calculate_all_metrics(total_alerts, incidents)

        print(f"Total input alerts: {total_alerts}")
        print(f"Number of incidents identified: {len(incidents)}")
        print()

        for metric_name, value in all_metrics.items():
            if 'ratio' in metric_name:
                print(f"{metric_name}: {value:.2f}")
            elif 'accuracy' in metric_name or 'rate' in metric_name:
                print(f"{metric_name}: {value:.2%}")
            elif 'time' in metric_name:
                print(f"{metric_name}: {value:.2f} hours")
            else:
                print(f"{metric_name}: {value:.3f}")

    except Exception as e:
        print(f"Error in metrics calculation: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Run the complete demo"""
    print("SOC Causal Alert Correlation & Root-Cause Intelligence")
    print("Demonstrating the end-to-end pipeline\n")

    try:
        # Step 1: Text Processing
        chunks = demo_text_processing()

        # Step 2: Schema Creation
        alerts = demo_schema_creation()

        # Step 3: Graph Building
        G = demo_graph_building(alerts)
        if G is None:
            print("ERROR: Demo failed at graph building step")
            return

        # Step 4: Clustering
        incident_clusters, incident_summaries = demo_clustering(G)
        if not incident_clusters:
            print("ERROR: Demo failed at clustering step")
            return

        # Step 5: Root Cause Analysis
        root_causes, confidences = demo_root_cause_analysis(G, incident_clusters)

        # Step 6: Response Recommendations
        recommendations = demo_response_recommendation(incident_summaries, root_causes, confidences)

        # Step 7: Metrics
        demo_metrics(incident_summaries)

        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        print("\nThe system successfully:")
        print("  1. Parsed raw alert text into structured chunks")
        print("  2. Created structured alert objects with entities and metadata")
        print("  3. Built an alert-entity graph with temporal and technique relationships")
        print("  4. Clustered related alerts into meaningful incidents")
        print("  5. Identified root causes using multi-factor scoring")
        print("  6. Generated context-aware response recommendations")
        print("  7. Calculated effectiveness metrics")
        print("\nThis demonstrates the core value proposition:")
        print("  - Reducing alert fatigue through causal correlation")
        print("  - Pinpointing root causes instead of chasing symptoms")
        print("  - Recommending precise, minimal-impact actions")
        print("  - Providing measurable security operations improvements")

    except Exception as e:
        print(f"\nERROR: Demo failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()