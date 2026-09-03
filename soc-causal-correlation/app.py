"""Streamlit interface for the local SOC alert-correlation workflow."""

import streamlit as st
import streamlit.components.v1 as components

from pipeline import alerts_from_text, analyze_alerts
from viz.graph_render import IncidentGraphRenderer


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
            a, b, c = st.columns(3)
            a.metric("Confidence", f"{incident.confidence_score:.0%}")
            b.write("**Likely root cause**", incident.root_cause_alert_id or "Unknown")
            c.write("**Recommended response**", incident.recommended_action)
            st.write("**Techniques:**", ", ".join(incident.attack_techniques) or "Not identified")
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


if __name__ == "__main__":
    main()
