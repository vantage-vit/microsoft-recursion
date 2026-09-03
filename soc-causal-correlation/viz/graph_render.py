"""
Graph rendering: pyvis rendering of incident graph for the UI
"""

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False
    print("Warning: pyvis not installed. Graph visualization will be limited.")

import networkx as nx
from typing import Dict, Any, Optional
import json

class IncidentGraphRenderer:
    def __init__(self, height: str = "600px", width: str = "100%", bgcolor: str = "#222222", font_color: str = "white"):
        """
        Initialize the graph renderer.

        Args:
            height: Height of the visualization
            width: Width of the visualization
            bgcolor: Background color
            font_color: Font color for nodes
        """
        self.height = height
        self.width = width
        self.bgcolor = bgcolor
        self.font_color = font_color

    def render_incident_graph(self, G: nx.Graph, incident_nodes: set = None,
                            highlight_root_cause: str = None,
                            show_physics: bool = True) -> str:
        """
        Render an incident subgraph as an interactive HTML visualization.

        Args:
            G: Full alert-entity graph
            incident_nodes: Set of node IDs to highlight (if None, show entire graph)
            highlight_root_cause: Alert ID of root cause to highlight
            show_physics: Whether to enable physics simulation

        Returns:
            HTML string of the visualization
        """
        if not PYVIS_AVAILABLE:
            return self._render_fallback(G, incident_nodes, highlight_root_cause)

        # Create a pyvis network
        net = Network(height=self.height, width=self.width,
                     bgcolor=self.bgcolor, font_color=self.font_color)

        # Determine which nodes to include
        if incident_nodes is None:
            nodes_to_include = set(G.nodes())
        else:
            nodes_to_include = set(incident_nodes)

        # Add nodes
        for node_id in nodes_to_include:
            if node_id not in G:
                continue

            node_data = G.nodes[node_id]
            node_type = node_data.get('type', 'unknown')

            # Set node properties based on type
            if node_type == 'alert':
                label = f"Alert: {node_data.get('alert_id', 'unknown')}"
                title = self._create_alert_tooltip(node_data)
                color = self._get_alert_color(node_data.get('severity', 'medium'))
                shape = 'dot'
                size = 25
            elif node_type == 'entity':
                entity_type = node_data.get('entity_type', 'unknown')
                entity_value = node_data.get('entity_value', 'unknown')
                label = f"{entity_type}: {str(entity_value)[:20]}..."
                title = f"Entity Type: {entity_type}\nValue: {entity_value}"
                color = self._get_entity_color(entity_type)
                shape = 'square'
                size = 20
            else:
                label = f"Unknown: {node_id}"
                title = f"Node ID: {node_id}\nType: {node_type}"
                color = '#gray'
                shape = 'dot'
                size = 15

            # Highlight root cause if specified
            if highlight_root_cause and node_type == 'alert' and \
               node_data.get('alert_id') == highlight_root_cause:
                color = '#ff0000'  # Red for root cause
                size = 30
                shape = 'star'

            # Highlight incident nodes
            if incident_nodes is not None and node_id in incident_nodes:
                # Increase size for incident nodes
                size = min(size + 5, 40)

            net.add_node(node_id, label=label, title=title, color=color,
                        shape=shape, size=size)

        # Add edges
        for u, v, edge_data in G.edges(data=True):
            if u in nodes_to_include and v in nodes_to_include:
                # Set edge properties based on relationship
                relationship = edge_data.get('relationship', 'unknown')
                weight = edge_data.get('weight', 1.0)

                # Color based on relationship type
                color = self._get_edge_color(relationship)
                width = max(1, min(weight * 5, 10))  # Scale width by weight

                # Tooltip for edge
                title = f"Relationship: {relationship}\nWeight: {weight:.2f}"

                net.add_edge(u, v, color=color, width=width, title=title)

        # Configure physics
        if show_physics:
            net.set_options("""
            var options = {
              "physics": {
                "forceAtlas2Based": {
                  "gravitationalConstant": -26,
                  "centralGravity": 0.005,
                  "springLength": 230
                },
                "maxVelocity": 146,
                "solver": "forceAtlas2Based",
                "timestep": 0.35,
                "stabilization": {"iterations": 150}
              }
            }
            """)
        else:
            net.set_options("""var options = { "physics": { "enabled": false } }""")

        # Generate HTML
        try:
            html = net.generate_html()
            return html
        except:
            return self._render_fallback(G, incident_nodes, highlight_root_cause)

    def _create_alert_tooltip(self, alert_data: Dict[str, Any]) -> str:
        """Create a detailed tooltip for an alert node."""
        tooltip_parts = [
            f"Alert ID: {alert_data.get('alert_id', 'unknown')}",
            f"Source: {alert_data.get('source_product', 'unknown')}",
            f"Type: {alert_data.get('alert_type', 'unknown')}",
            f"Severity: {alert_data.get('severity', 'unknown')}",
            f"Time: {alert_data.get('timestamp', 'unknown')}",
        ]

        # Add entities
        entities = alert_data.get('entities', {})
        if entities:
            entity_parts = []
            for k, v in entities.items():
                if v:
                    entity_parts.append(f"{k}: {v}")
            if entity_parts:
                tooltip_parts.append("Entities: " + ", ".join(entity_parts))

        # Add MITRE technique
        technique = alert_data.get('mitre_technique')
        if technique:
            tooltip_parts.append(f"MITRE Technique: {technique}")

        # Add raw text (truncated)
        raw_text = alert_data.get('raw_text', '')
        if raw_text:
            if len(raw_text) > 100:
                raw_text = raw_text[:97] + "..."
            tooltip_parts.append(f"Raw Text: {raw_text}")

        return "\n".join(tooltip_parts)

    def _get_alert_color(self, severity: str) -> str:
        """Get color for alert based on severity."""
        color_map = {
            'critical': '#ff0000',  # Red
            'high': '#ff6600',      # Orange
            'medium': '#ffcc00',    # Yellow
            'low': '#66cc00',       # Light green
            'unknown': '#cccccc'    # Gray
        }
        return color_map.get(severity.lower(), '#cccccc')

    def _get_entity_color(self, entity_type: str) -> str:
        """Get color for entity based on type."""
        color_map = {
            'user': '#0066ff',      # Blue
            'host': '#00cc66',      # Green
            'ip': '#cc00cc',        # Purple
            'process': '#ff6666',   # Light red
            'file': '#6666ff',      # Light blue
            'cloud_role': '#ff9900', # Orange
            'domain': '#66ff66',    # Light green
            'unknown': '#cccccc'    # Gray
        }
        return color_map.get(entity_type.lower(), '#cccccc')

    def _get_edge_color(self, relationship: str) -> str:
        """Get color for edge based on relationship type."""
        color_map = {
            'mentions': '#888888',      # Gray
            'temporal_proximity': '#00ccff', # Cyan
            'shared_technique': '#ff66ff',   # Magenta
            'temporal': '#00ccff',     # Cyan
            'unknown': '#cccccc'       # Gray
        }
        return color_map.get(relationship.lower(), '#cccccc')

    def _render_fallback(self, G: nx.Graph, incident_nodes: set = None,
                        highlight_root_cause: str = None) -> str:
        """
        Fallback rendering when pyvis is not available.
        Returns a simple JSON representation.
        """
        data = {
            'nodes': [],
            'edges': []
        }

        nodes_to_include = set(G.nodes()) if incident_nodes is None else set(incident_nodes)

        for node_id in nodes_to_include:
            if node_id not in G:
                continue
            node_data = G.nodes[node_id]
            data['nodes'].append({
                'id': node_id,
                'label': f"{node_data.get('type', 'unknown')}: {node_id}",
                'type': node_data.get('type', 'unknown'),
                'data': node_data
            })

        for u, v, edge_data in G.edges(data=True):
            if u in nodes_to_include and v in nodes_to_include:
                data['edges'].append({
                    'source': u,
                    'target': v,
                    'relationship': edge_data.get('relationship', 'unknown'),
                    'weight': edge_data.get('weight', 1.0),
                    'data': edge_data
                })

        return json.dumps(data, indent=2, default=str)

def render_incident_summary(G: nx.Graph, incident_nodes: set) -> str:
    """
    Create a text summary of an incident for display.

    Args:
        G: Full alert-entity graph
        incident_nodes: Set of node IDs in the incident

    Returns:
        Formatted string summary
    """
    from ..graph.clustering import summarize_incident

    summary = summarize_incident(G, incident_nodes)

    lines = [
        f"INCIDENT SUMMARY: {summary['incident_id']}",
        "-" * 40,
        f"Alerts: {summary['alert_count']}",
        f"Entities: {summary['entity_count']}",
        f"Time Span: {summary['time_span_hours']:.2f} hours" if summary['time_span_hours'] else "Time Span: Unknown",
        f"Sources: {', '.join(summary['sources'])}",
        f"Techniques: {', '.join(summary['techniques'])}" if summary['techniques'] else "Techniques: None",
        f"Entity Types: {', '.join([f'{k}:{v}' for k, v in summary['entity_types'].items()])}",
        f"Graph Density: {summary['density']:.3f}"
    ]

    return "\n".join(lines)

if __name__ == "__main__":
    # Test the renderer with mock data
    import networkx as nx
    from datetime import datetime, timedelta

    # Create mock graph
    G = nx.Graph()

    # Add alert nodes
    now = datetime.now()
    G.add_node("alert_001", type='alert', alert_id="alert_001",
              timestamp=(now - timedelta(hours=3)).isoformat(),
              source_product="Identity Platform", alert_type="Failed login",
              severity="medium", mitre_technique="T1110",
              raw_text="2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com",
              entities={"user": "j.suresh@acmecorp.com"})

    G.add_node("alert_002", type='alert', alert_id="alert_002",
              timestamp=(now - timedelta(hours=2, minutes=30)).isoformat(),
              source_product="Identity Platform", alert_type="Successful login",
              severity="medium", mitre_technique="T1078",
              raw_text="2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com",
              entities={"user": "j.suresh@acmecorp.com"})

    G.add_node("alert_003", type='alert', alert_id="alert_003",
              timestamp=(now - timedelta(hours=2)).isoformat(),
              source_product="Endpoint (EDR)", alert_type="PowerShell activity",
              severity="high", mitre_technique="T1059.001",
              raw_text="2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41",
              entities={"host": "DESKTOP-7QK41", "process": "powershell.exe"})

    # Add entity nodes
    G.add_node("entity_user_jdoe", type='entity', entity_type="user",
              entity_value="j.suresh@acmecorp.com")
    G.add_node("entity_host_desktop", type='entity', entity_type="host",
              entity_value="DESKTOP-7QK41")

    # Add edges
    G.add_edge("alert_001", "entity_user_jdoe", relationship='mentions', weight=1.0)
    G.add_edge("alert_002", "entity_user_jdoe", relationship='mentions', weight=1.0)
    G.add_edge("alert_003", "entity_host_desktop", relationship='mentions', weight=1.0)
    G.add_edge("alert_001", "alert_002", relationship='temporal_proximity', weight=0.8)
    G.add_edge("alert_002", "alert_003", relationship='temporal_proximity', weight=0.7)

    # Test rendering
    renderer = IncidentGraphRenderer()
    print("Testing graph renderer...")
    print(f"PyVis available: {PYVIS_AVAILABLE}")

    # Render full graph
    html_output = renderer.render_incident_graph(G)
    if PYVIS_AVAILABLE:
        print("Generated HTML visualization (first 500 chars):")
        print(html_output[:500] + "..." if len(html_output) > 500 else html_output)
    else:
        print("Fallback JSON output:")
        print(html_output)

    # Render incident subgraph
    incident_nodes = {"alert_001", "alert_002", "alert_003", "entity_user_jdoe", "entity_host_desktop"}
    incident_html = renderer.render_incident_graph(G, incident_nodes=incident_nodes,
                                                 highlight_root_cause="alert_001")
    print("\nIncident subgraph rendered")

    # Test summary
    summary = render_incident_summary(G, incident_nodes)
    print("\nIncident Summary:")
    print(summary)