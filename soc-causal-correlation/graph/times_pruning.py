"""
Time pruning: prunes entity edges outside time-window (lateral movement logic)
"""

import networkx as nx
from typing import Dict, Any
from datetime import datetime, timedelta
try:
    # Try relative imports (when used as package)
    from ..schema import Alert
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Alert

def prune_entity_edges_by_time(G: nx.Graph, time_window_hours: float = 24.0) -> nx.Graph:
    """
    Prune entity edges that are too old based on alert timestamps.
    This helps prevent linking unrelated activities through long-lived entities
    (like service accounts) that persist for months.

    Args:
        G: NetworkX graph with alert and entity nodes
        time_window_hours: Maximum age in hours for considering entity connections valid

    Returns:
        Graph with old entity edges removed
    """
    # Create a copy to avoid modifying original during iteration
    G_pruned = G.copy()

    # Current time for reference (in real system, this would be analysis time)
    # For MVP, we'll use the latest alert timestamp as reference
    latest_time = _get_latest_alert_timestamp(G)
    if latest_time is None:
        return G_pruned  # No timestamps, can't prune

    cutoff_time = latest_time - timedelta(hours=time_window_hours)

    # Find entity nodes
    entity_nodes = [n for n, data in G_pruned.nodes(data=True) if data.get('type') == 'entity']

    edges_to_remove = []

    for entity_node in entity_nodes:
        entity_data = G_pruned.nodes[entity_node]
        # Check if this entity has a "last_seen" timestamp or similar
        # For MVP, we'll check connected alerts for their timestamps

        connected_alerts = []
        for neighbor in G_pruned.neighbors(entity_node):
            neighbor_data = G_pruned.nodes[neighbor]
            if neighbor_data.get('type') == 'alert' and neighbor_data.get('timestamp'):
                try:
                    alert_time = _parse_timestamp(neighbor_data['timestamp'])
                    if alert_time:
                        connected_alerts.append((neighbor, alert_time))
                except:
                    pass

        # If entity is only connected to very old alerts, consider pruning edges
        old_connections = []
        recent_connections = []

        for alert_node, alert_time in connected_alerts:
            if alert_time < cutoff_time:
                old_connections.append((alert_node, alert_time))
            else:
                recent_connections.append((alert_node, alert_time))

        # If all connections are old, we might want to prune
        # But for lateral movement detection, we keep some historical context
        # For now, we'll implement a simple approach: if entity is connected
        # only to alerts older than threshold, and it's a high-risk entity type,
        # we might want to investigate rather than prune

        # Actually, for causal correlation, we want to keep entity connections
        # that could represent attack chains, even if slightly older
        # So we'll be conservative and only prune very old connections
        # to extremely persistent entities like domain controllers

        entity_type = entity_data.get('entity_type', '')
        is_persistent_entity = entity_type in ['domain_controller', 'service_account', 'admin_user']

        if not is_persistent_entity and old_connections and not recent_connections:
            # This entity is only connected to old alerts and isn't persistently risky
            # Mark edges for removal
            for alert_node, _ in old_connections:
                if G_pruned.has_edge(alert_node, entity_node):
                    edges_to_remove.append((alert_node, entity_node))

    # Remove the edges
    for u, v in edges_to_remove:
        if G_pruned.has_edge(u, v):
            G_pruned.remove_edge(u, v)
            # Optionally, log or track what was pruned
            # print(f"Pruned edge between {u} and {v} due to age")

    return G_pruned

def _get_latest_alert_timestamp(G: nx.Graph) -> datetime:
    """Extract the latest timestamp from alert nodes in the graph."""
    latest = None

    for node_id, node_data in G.nodes(data=True):
        if node_data.get('type') == 'alert' and node_data.get('timestamp'):
            try:
                ts = _parse_timestamp(node_data['timestamp'])
                if ts and (latest is None or ts > latest):
                    latest = ts
            except:
                pass

    return latest

def _parse_timestamp(ts_str: str) -> datetime:
    """Parse timestamp string into datetime object."""
    if not ts_str or not isinstance(ts_str, str):
        return None

    # Clean up the string
    ts_str = ts_str.strip().replace(' ', 'T')

    # Try common formats
    formats = [
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%fZ'
    ]

    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue

    # If none worked, try removing timezone info and trying again
    if '+' in ts_str:
        ts_str = ts_str.split('+')[0]
    if 'Z' in ts_str:
        ts_str = ts_str.replace('Z', '')

    for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue

    return None

def add_entity_decay_weights(G: nx.Graph, half_life_hours: float = 168.0) -> nx.Graph:
    """
    Add decay weights to entity edges based on alert age.
    Older connections get lower weights, representing decreased confidence
    in causal relationship over time.

    Args:
        G: NetworkX graph
        half_life_hours: Half-life for exponential decay (default 1 week)

    Returns:
        Graph with updated edge weights incorporating time decay
    """
    G_weighted = G.copy()
    latest_time = _get_latest_alert_timestamp(G_weighted)

    if latest_time is None:
        return G_weighted

    # Decay factor: weight = 0.5^(time_diff / half_life)
    for u, v, edge_data in G_weighted.edges(data=True):
        # Check if this is an alert-entity edge
        u_data = G_weighted.nodes[u]
        v_data = G_weighted.nodes[v]

        is_alert_entity_edge = (
            (u_data.get('type') == 'alert' and v_data.get('type') == 'entity') or
            (u_data.get('type') == 'entity' and v_data.get('type') == 'alert')
        )

        if is_alert_entity_edge:
            # Get the alert node
            alert_node = u if u_data.get('type') == 'alert' else v
            alert_data = G_weighted.nodes[alert_node]
            alert_time_str = alert_data.get('timestamp')

            if alert_time_str:
                try:
                    alert_time = _parse_timestamp(alert_time_str)
                    if alert_time:
                        time_diff_hours = (latest_time - alert_time).total_seconds() / 3600
                        decay_factor = 0.5 ** (time_diff_hours / half_life_hours)

                        # Apply decay to existing weight
                        original_weight = edge_data.get('weight', 1.0)
                        new_weight = original_weight * decay_factor
                        G_weighted[u][v]['weight'] = max(0.01, new_weight)  # Minimum weight
                        G_weighted[u][v]['time_decay_applied'] = True
                        G_weighted[u][v]['hours_since_alert'] = time_diff_hours
                except:
                    pass  # Keep original weight if timestamp parsing fails

    return G_weighted

if __name__ == "__main__":
    # Test with mock graph
    import networkx as nx
    from datetime import datetime, timedelta

    # Create a simple test graph
    G = nx.Graph()

    # Add alert nodes with timestamps
    now = datetime.now()
    old_time = now - timedelta(hours=30)  # 30 hours ago
    recent_time = now - timedelta(hours=2)  # 2 hours ago

    G.add_node("alert_old", type='alert', timestamp=old_time.isoformat(), source_product="Test")
    G.add_node("alert_recent", type='alert', timestamp=recent_time.isoformat(), source_product="Test")
    G.add_node("entity_test", type='entity', entity_type="user", entity_value="testuser")

    # Add edges
    G.add_edge("alert_old", "entity_test", weight=1.0)
    G.add_edge("alert_recent", "entity_test", weight=1.0)

    print(f"Original graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print(f"Edge weights: {[G[u][v].get('weight', 1.0) for u, v in G.edges()]}")

    # Apply time pruning (shouldn't remove edges in 24h window with 30h old alert)
    G_pruned = prune_entity_edges_by_time(G, time_window_hours=24.0)
    print(f"After pruning (24h): {G_pruned.number_of_edges()} edges")

    # Apply decay weights
    G_decayed = add_entity_decay_weights(G, half_life_hours=24.0)
    print("After decay weighting:")
    for u, v in G_decayed.edges():
        weight = G_decayed[u][v].get('weight', 1.0)
        hours = G_decayed[u][v].get('hours_since_alert', 'N/A')
        print(f"  {u} -- {v}: weight={weight:.3f}, hours={hours}")