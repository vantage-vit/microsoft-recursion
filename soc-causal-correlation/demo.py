"""Run the complete offline SOC-correlation workflow on representative alerts."""

from pipeline import alerts_from_text, analyze_alerts


SAMPLE_ALERTS = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
2023-01-15 09:24:55 Cloud (AWS): New cloud role assumed - arn:aws:iam::role/finance-read
2023-01-15 09:41:03 Firewall: Outbound transfer - 2.3GB to unrecognized IP 203.0.113.44"""


def main() -> None:
    alerts = alerts_from_text(SAMPLE_ALERTS)
    # Increase weight threshold to break alert-alert edges
    result = analyze_alerts(alerts, time_window_seconds=1800, min_alerts=1, weight_threshold=0.95)
    print(f"Processed {len(alerts)} alerts into {len(result['incidents'])} incidents.")
    for incident, summary in zip(result["incidents"], result["summaries"]):
        print(f"\n{incident.incident_id}")
        print(f"  Alerts: {', '.join(incident.alert_ids)}")
        print(f"  Root cause: {incident.root_cause_alert_id}")
        print(f"  Confidence: {incident.confidence_score:.0%}")
        print(f"  Techniques: {', '.join(incident.attack_techniques) or 'not identified'}")
        print(f"  Response: {incident.recommended_action}")
        print(f"  Graph density: {summary['density']:.2f}")


if __name__ == "__main__":
    main()
