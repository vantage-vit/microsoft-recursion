"""Streamlit interface for the local SOC alert-correlation workflow."""

import streamlit as st
import streamlit.components.v1 as components
import networkx as nx
from pathlib import Path
from datetime import datetime

from pipeline import alerts_from_text, analyze_alerts
from viz.graph_render import IncidentGraphRenderer

# ----------------------------------------------------------------------
# Error logging setup
# ----------------------------------------------------------------------
ERROR_LOG = Path(__file__).parent / "logs" / "errors.log"
ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)

def log_error(message: str, source: str = "ErrorGenerator") -> None:
    """
    Append a single line to logs/errors.log.
    The line format matches what the heuristic normaliser expects:
        <timestamp> <source>: <message>
    """
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with ERROR_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{ts} {source}: {message}\n")

# ----------------------------------------------------------------------
# Helper to read new lines from the error log since last read
# ----------------------------------------------------------------------
def get_new_error_lines() -> list[str]:
    """Return new lines appended to ERROR_LOG since last call and update the stored position."""
    if "log_last_pos" not in st.session_state:
        st.session_state.log_last_pos = 0

    lines = []
    try:
        with ERROR_LOG.open("r", encoding="utf-8") as f:
            f.seek(st.session_state.log_last_pos)
            new_data = f.read()
            if new_data:
                lines = [ln.rstrip("\n") for ln in new_data.splitlines() if ln.strip()]
                st.session_state.log_last_pos = f.tell()
    except FileNotFoundError:
        # If the log file hasn't been created yet, treat as no new lines.
        pass
    return lines

# ----------------------------------------------------------------------
# Process new error lines through the existing correlation pipeline
# ----------------------------------------------------------------------
def process_error_lines(time_window_minutes: int, min_alerts: int) -> dict | None:
    """
    Pull new error lines from the log, normalise them, run the correlation pipeline,
    and return a dict compatible with the existing rendering code.
    Returns None if there were no new lines.
    """
    lines = get_new_error_lines()
    if not lines:
        return None

    raw_text = "\n".join(lines)        # one alert per line
    alerts = alerts_from_text(raw_text)
    result = analyze_alerts(
        alerts,
        time_window_seconds=time_window_minutes * 60,
        min_alerts=int(min_alerts),
    )
    # Include the alerts list so the rendering function can show metrics etc.
    result["alerts"] = alerts
    return result

# ----------------------------------------------------------------------
# Display helper – reuse the same rendering logic as the normal alerts
# ----------------------------------------------------------------------
def display_correlation_result(result: dict) -> None:
    """Render the correlation result using the same widgets as the normal flow."""
    if not result or not result.get("incidents"):
        st.info("No incident met the selected minimum. Reduce the minimum alert count or widen the time window.")
        return

    incidents = result["incidents"]
    summaries = result["summaries"]
    graph = result["graph"]
    clusters = result["clusters"]
    alerts = result["alerts"]

    st.subheader("🔎 Correlation result")
    first, second, third = st.columns(3)
    first.metric("Input alerts", len(alerts))
    second.metric("Correlated incidents", len(incidents))
    third.metric(
        "Compression",
        f"{len(alerts) / len(incidents):.1f}×" if incidents else "—",
    )

    if not incidents:
        st.info("No cluster met the selected minimum. Reduce the minimum alert count or widen the time window.")
        return

    renderer = IncidentGraphRenderer(height="520px")
    for incident, summary, cluster in zip(incidents, summaries, clusters):
        # Build a subgraph containing only the nodes and edges of this incident
        subgraph = graph.subgraph(cluster).copy()
        with st.expander(
            f"{incident.incident_id} — {len(incident.alert_ids)} alerts", expanded=True
        ):
            a, b, c = st.columns(3)
            a.metric("Confidence", f"{incident.confidence_score:.0%}")
            b.markdown(f"**Likely root cause**  \n{incident.root_cause_alert_id or 'Unknown'}")
            c.markdown(f"**Recommended response**  \n{incident.recommended_action}")
            st.markdown(f"**Techniques:** {', '.join(incident.attack_techniques) or 'Not identified'}")
            st.dataframe(summary["alerts"], use_container_width=True, hide_index=True)
            graph_html = renderer.render_incident_graph(
                subgraph,
                incident_nodes=None,  # subgraph already filtered
                highlight_root_cause=incident.root_cause_alert_id,
            )
            if graph_html.lstrip().startswith("{"):
                st.json(graph_html)
            else:
                components.html(graph_html, height=540, scrolling=True)


# ----------------------------------------------------------------------
# Main Streamlit app
# ----------------------------------------------------------------------
SAMPLE_ALERTS = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
2023-01-15 09:24:55 Cloud (AWS): New cloud role assumed - arn:aws:iam::role/finance-read
2023-01-15 09:41:03 Firewall: Outbound transfer - 2.3GB to unrecognized IP 203.0.113.44"""


def main() -> None:
    st.set_page_config(page_title="SOC Causal Correlation", layout="wide")
    st.title("Causal SOC Alert Correlation")
    st.caption("Paste timestamped alerts to group related activity, identify a likely root cause, and get a scoped response recommendation.")
    raw_text = st.text_area("Security alerts", value=SAMPLE_ALERTS, height=220)
    left, middle, right = st.columns(3)
    with left:
        time_window = st.slider(
            "Correlation window (minutes)", 5, 240, 30, key="time_window_slider"
        )
    with middle:
        min_alerts = st.number_input(
            "Minimum alerts per incident", 1, 20, 2, key="min_alerts_input"
        )
    with right:
        st.write("")
        analyze = st.button("Analyze alerts", type="primary", use_container_width=True)

    if analyze:
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
                a, b, c = st.columns(3)
                a.metric("Confidence", f"{incident.confidence_score:.0%}")
                b.markdown(f"**Likely root cause**  \n{incident.root_cause_alert_id or 'Unknown'}")
                c.markdown(f"**Recommended response**  \n{incident.recommended_action}")
                st.markdown(f"**Techniques:** {', '.join(incident.attack_techniques) or 'Not identified'}")
                st.dataframe(summary["alerts"], use_container_width=True, hide_index=True)
                graph_html = renderer.render_incident_graph(
                    result["graph"],
                    incident_nodes=cluster,
                    highlight_root_cause=incident.root_cause_alert_id,
                )
                if graph_html.lstrip().startswith("{"):
                    st.json(graph_html)
                else:
                    components.html(graph_html, height=540, scrolling=True)

    st.divider()
    st.subheader("🚨 Error‑injection demo")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("💥 Inject a synthetic error"):
            # Inject a few sample error lines
            log_error(
                "Traceback (most recent call last):\n  File \"demo.py\", line 13, in <module>\n  raise ValueError('demo failure')"
            )
            log_error("Failed to connect to upstream service: timeout after 30s")
            log_error("Invalid token received from user alice@example.com")
            st.success("Injected 3 error lines – press ▶️ Check for new errors to see the correlation.")
    with col2:
        if st.button("▶️ Check for new errors (manual)"):
            err_res = process_error_lines(time_window, min_alerts)
            if err_res is None:
                st.info("No new error lines were found.")
            else:
                display_correlation_result(err_res)

    # Optional: auto‑refresh every 4 seconds (uncomment if you installed streamlit‑autorefresh)
    # from streamlit_autorefresh import st_autorefresh
    # _ = st_autorefresh(interval=4000, limit=None, key="error_auto_refresh")
    # if _:   # runs on each refresh after the first
    #     err_res = process_error_lines(time_window, min_alerts)
    #     if err_res:
    #         st.subheader("🔴 Live error correlation (auto‑refresh)")
    #         display_correlation_result(err_res)


if __name__ == "__main__":
    main()