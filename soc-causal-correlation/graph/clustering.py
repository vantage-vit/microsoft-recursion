"""
Clustering: connected_components / Louvain -> incident groups
"""

import networkx as nx
from typing import List, Dict, Any, Set
try:
    # Try relative imports (when used as package)
    from ..schema import Alert
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Alert

# Try to import python-louvain for community detection
try:
    import community  # python-louvain
    LOUVAIN_AVAILABLE = True
except ImportError:
    LOUVAIN_AVAILABLE = False
    print("Warning: python-louvain not installed. Louvain clustering will not be available.")

def find_incident_clusters(G: nx.Graph, method: str = "connected_components") -> List[Set[str]]:
    """
    Find incident clusters in the alert-entity graph.

    Args:
        G: NetworkX graph with alerts and entities
        method: Clustering method - "connected_components" or "louvain"

    Returns:
        List of sets, where each set contains node IDs belonging to one incident
    """
    if method == "connected_components":
        return _find_connected_components(G)
    elif method == "louvain":
        if not LOUVAIN_AVAILABLE:
            print("Warning: Louvain method not available, falling back to connected components")
            return _find_connected_components(G)
        return _find_louvain_communities(G)
    else:
        raise ValueError(f"Unknown clustering method: {method}")

def _find_connected_components(G: nx.Graph) -> List[Set[str]]:
    """
    Find connected components in the graph.
    Each connected component represents a potentially related group of alerts/entities.
    """
    components = list(nx.connected_components(G))
    return components

def _find_louvain_communities(G: nx.Graph) -> List[Set[str]]:
    """
    Find communities using Louvain method for weighted graphs.
    Better for detecting subtle community structures in weighted graphs.
    """
    if G.number_of_edges() == 0:
        # No edges, each node is its own component
        return [{node} for node in G.nodes()]

    # Louvain method works best with weighted graphs
    # Use edge weights if available, otherwise treat all edges as weight 1.0
    try:
        partition = community.best_partition(G, weight='weight')
    except:
        # Fallback to unweighted if weight attribute causes issues
        partition = community.best_partition(G)

    # Group nodes by community ID
    communities = {}
    for node, community_id in partition.items():
        if community_id not in communities:
            communities[community_id] = set()
        communities[community_id].add(node)

    return list(communities.values())

def filter_incidents_by_size(clusters: List[Set[str]],
                           min_alerts: int = 2,
                           max_alerts: int = 1000) -> List[Set[str]]:
    """
    Filter incident clusters by size (number of alerts).

    Args:
        clusters: List of node sets from clustering
        min_alerts: Minimum number of alerts required for an incident
        max_alerts: Maximum number of alerts (to filter out noise clusters)

    Returns:
        Filtered list of incident clusters
    """
    filtered = []

    for cluster in clusters:
        # Count alert nodes in this cluster
        alert_count = 0
        for node in cluster:
            # This assumes we have access to node data to check type
            # For now, we'll approximate by checking if node ID starts with "alert_"
            if node.startswith("alert_"):
                alert_count += 1

        if min_alerts <= alert_count <= max_alerts:
            filtered.append(cluster)

    return filtered

def get_incident_subgraph(G: nx.Graph, incident_nodes: Set[str]) -> nx.Graph:
    """
    Extract subgraph for a specific incident.

    Args:
        G: Full alert-entity graph
        incident_nodes: Set of node IDs belonging to the incident

    Returns:
        Subgraph containing only the incident's nodes and edges
    """
    return G.subgraph(incident_nodes).copy()

def summarize_incident(G: nx.Graph, incident_nodes: Set[str]) -> Dict[str, Any]:
    """
    Create a summary of an incident for further analysis.

    Args:
        G: Full alert-entity graph
        incident_nodes: Set of node IDs belonging to the incident

    Returns:
        Dictionary with incident summary information
    """
    subgraph = get_incident_subgraph(G, incident_nodes)

    # Extract alert nodes
    alert_nodes = [n for n in incident_nodes if n.startswith("alert_")]
    entity_nodes = [n for n in incident_nodes if not n.startswith("alert_")]

    # Get alert details
    alerts = []
    timestamps = []
    sources = set()
    severities = []
    techniques = set()

    for node_id in alert_nodes:
        node_data = G.nodes[node_id]
        alerts.append({
            'alert_id': node_data.get('alert_id'),
            'timestamp': node_data.get('timestamp'),
            'source_product': node_data.get('source_product'),
            'alert_type': node_data.get('alert_type'),
            'severity': node_data.get('severity'),
            'raw_text': node_data.get('raw_text'),
            'mitre_technique': node_data.get('mitre_technique')
        })

        # Collect timestamps for time range calculation
        if node_data.get('timestamp'):
            try:
                from datetime import datetime
                ts = node_data['timestamp'].replace(' ', 'T')
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                timestamps.append(dt)
            except:
                pass

        sources.add(node_data.get('source_product', 'unknown'))
        severities.append(node_data.get('severity', 'unknown'))
        if node_data.get('mitre_technique'):
            techniques.add(node_data.get('mitre_technique'))

    # Calculate time span
    time_span_hours = None
    if timestamps:
        time_span_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600

    # Count entity types
    entity_types = {}
    for node_id in entity_nodes:
        node_data = G.nodes[node_id]
        entity_type = node_data.get('entity_type', 'unknown')
        entity_types[entity_type] = entity_types.get(entity_type, 0) + 1

    return {
        'incident_id': f"incident_{hash(tuple(sorted(incident_nodes))) % 100000:05d}",
        'alert_count': len(alert_nodes),
        'entity_count': len(entity_nodes),
        'alerts': alerts,
        'time_span_hours': time_span_hours,
        'sources': list(sources),
        'severity_distribution': {s: severities.count(s) for s in set(severities)},
        'techniques': list(techniques),
        'entity_types': entity_types,
        'density': nx.density(subgraph) if subgraph.number_of_nodes() > 1 else 0.0
    }

if __name__ == "__main__":
    # Test clustering with mock graph
    import networkx as nx
    from datetime import datetime, timedelta

    # Create mock graph representing two separate incidents
    G = nx.Graph()

    # Incident 1: Credential theft -> lateral movement
    incident1_alerts = [
        ("alert_1_1", {"timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
                      "source_product": "Identity Platform", "alert_type": "Failed login",
                      "severity": "medium", "mitre_technique": "T1110"}),
        ("alert_1_2", {"timestamp": (datetime.now() - timedelta(hours=4, minutes=30)).isoformat(),
                      "source_product": "Identity Platform", "alert_type": "Successful login",
                      "severity": "medium", "mitre_technique": "T1078"}),
        ("alert_1_3", {"timestamp": (datetime.now() - timedelta(hours=4)).isoformat(),
                      "source_product": "Endpoint (EDR)", "alert_type": "Process execution",
                      "severity": "high", "mitre_technique": "T1059.001"})
    ]

    # Incident 2: Data exfiltration
    incident2_alerts = [
        ("alert_2_1", {"timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                      "source_product": "Firewall", "alert_type": "Large outbound transfer",
                      "severity": "critical", "mitre_technique": "T1041"}),
        ("alert_2_2", {"timestamp": (datetime.now() - timedelta(hours=1, minutes=30)).isoformat(),
                      "source_product": "Cloud Proxy", "alert_type": "Cloud storage access",
                      "severity": "high", "mitre_technique": "T1567.001"})
    ]

    # Add alert nodes
    for alert_id, data in incident1_alerts + incident2_alerts:
        G.add_node(alert_id, type='alert', **data)

    # Add entity nodes
    entities = [
        ("entity_user_jdoe", {"entity_type": "user", "entity_value": "j.suresh@acmecorp.com"}),
        ("entity_host_desktop", {"entity_type": "host", "entity_value": "DESKTOP-7QK41"}),
        ("entity_ip_external", {"entity_type": "ip", "entity_value": "203.0.113.44"}),
        ("entity_cloud_role", {"entity_type": "cloud_role", "entity_value": "arn:aws:iam::role/finance-read"})
    ]

    for entity_id, data in entities:
        G.add_node(entity_id, type='entity', **data)

    # Add edges (alert-entity connections)
    # Incident 1 edges
    G.add_edge("alert_1_1", "entity_user_jdoe", weight=1.0)
    G.add_edge("alert_1_2", "entity_user_jdoe", weight=1.0)
    G.add_edge("alert_1_3", "entity_host_desktop", weight=1.0)

    # Incident 2 edges
    G.add_edge("alert_2_1", "entity_ip_external", weight=1.0)
    G.add_edge("alert_2_2", "entity_ip_external", weight=1.0)
    G.add_edge("alert_2_2", "entity_cloud_role", weight=1.0)

    # Add temporal edges (simplified)
    G.add_edge("alert_1_1", "alert_1_2", weight=0.8, relationship='temporal')
    G.add_edge("alert_1_2", "alert_1_3", weight=0.7, relationship='temporal')
    G.add_edge("alert_2_1", "alert_2_2", weight=0.9, relationship='temporal')

    print(f"Test graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Test connected components
    components_cc = find_incident_clusters(G, method="connected_components")
    print(f"\nConnected components: {len(components_cc)} clusters")
    for i, component in enumerate(components_cc):
        alert_count = sum(1 for node in component if node.startswith("alert_"))
        print(f"  Cluster {i+1}: {alert_count} alerts, {len(component)} total nodes")

    # Test Louvain
    if LOUVAIN_AVAILABLE:
        components_louvain = find_incident_clusters(G, method="louvain")
        print(f"\nLouvain communities: {len(components_louvain)} clusters")
        for i, component in enumerate(components_louvain):
            alert_count = sum(1 for node in component if node.startswith("alert_"))
            print(f"  Cluster {i+1}: {alert_count} alerts, {len(component)} total nodes")
    else:
        print("\nLouvain method not available (python-louvain not installed)")

    # Test incident summarization
    if components_cc:
        print(f"\nIncident summary for first cluster:")
        summary = summarize_incident(G, components_cc[0])
        print(f"  Incident ID: {summary['incident_id']}")
        print(f"  Alerts: {summary['alert_count']}")
        print(f"  Time span: {summary['time_span_hours']:.2f} hours")
        print(f"  Sources: {summary['sources']}")
        print(f"  Techniques: {summary['techniques']}")