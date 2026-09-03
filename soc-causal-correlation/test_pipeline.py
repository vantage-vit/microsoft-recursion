"""End-to-end regression tests for the local correlation workflow."""

import unittest

from pipeline import alerts_from_text, analyze_alerts


SAMPLE = """2024-01-01 10:00:00 Identity: Five failed logins for a@example.com
2024-01-01 10:05:00 Identity: Successful login from unrecognized device for a@example.com
2024-01-01 10:10:00 EDR: PowerShell spawned with encoded command on DESKTOP-1"""


class PipelineTests(unittest.TestCase):
    def test_alerts_keep_timestamps_and_techniques(self):
        alerts = alerts_from_text(SAMPLE)
        self.assertEqual(3, len(alerts))
        self.assertTrue(all(alert.timestamp for alert in alerts))
        self.assertEqual("T1110", alerts[0].mitre_technique)

    def test_pipeline_returns_a_complete_incident(self):
        result = analyze_alerts(alerts_from_text(SAMPLE), time_window_seconds=900)
        self.assertEqual(1, len(result["incidents"]))
        incident = result["incidents"][0]
        self.assertEqual(3, len(incident.alert_ids))
        self.assertIsNotNone(incident.root_cause_alert_id)
        self.assertGreater(incident.confidence_score, 0)
        self.assertTrue(incident.recommended_action)
        self.assertIn("mitre_technique", result["graph"].nodes["alert_alert_001"])

    def test_incident_ids_are_stable(self):
        first = analyze_alerts(alerts_from_text(SAMPLE), time_window_seconds=900)
        second = analyze_alerts(alerts_from_text(SAMPLE), time_window_seconds=900)
        self.assertEqual(first["incidents"][0].incident_id, second["incidents"][0].incident_id)


if __name__ == "__main__":
    unittest.main()
