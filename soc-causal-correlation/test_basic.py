"""
Basic test to verify the system components work together
"""

import sys
import os

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, '..'))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")

    try:
        from schema import Alert, Incident
        print("[PASS] Schema imports successful")
    except Exception as e:
        print(f"[FAIL] Schema imports failed: {e}")
        return False

    try:
        from ingestion.text_input import split_into_alert_chunks
        print("[PASS] Text input imports successful")
    except Exception as e:
        print(f"[FAIL] Text input imports failed: {e}")
        return False

    try:
        from graph.build_graph import build_alert_entity_graph
        print("[PASS] Graph build imports successful")
    except Exception as e:
        print(f"[FAIL] Graph build imports failed: {e}")
        return False

    try:
        from analysis.root_cause import identify_root_cause
        print("[PASS] Root cause imports successful")
    except Exception as e:
        print(f"[FAIL] Root cause imports failed: {e}")
        return False

    try:
        from analysis.response_recommender import recommend_response
        print("[PASS] Response recommender imports successful")
    except Exception as e:
        print(f"[FAIL] Response recommender imports failed: {e}")
        return False

    try:
        from evaluation.metrics import SecurityMetrics
        print("[PASS] Metrics imports successful")
    except Exception as e:
        print(f"[FAIL] Metrics imports failed: {e}")
        return False

    try:
        from viz.graph_render import IncidentGraphRenderer
        print("[PASS] Viz imports successful")
    except Exception as e:
        print(f"[FAIL] Viz imports failed: {e}")
        return False

    return True

def test_schema_creation():
    """Test creating schema objects"""
    print("\nTesting schema creation...")

    try:
        from schema import Alert, AlertEntities, Incident
        from datetime import datetime

        alert = Alert(
            alert_id="test_001",
            timestamp=datetime.now(),
            source_product="Test Product",
            alert_type="Test Alert",
            severity="medium",
            entities=AlertEntities(user="test@example.com"),
            raw_text="This is a test alert",
            mitre_technique="T1110"
        )

        print("[PASS] Alert creation successful")
        print(f"  Alert ID: {alert.alert_id}")
        print(f"  Source: {alert.source_product}")
        print(f"  Severity: {alert.severity}")

        incident = Incident(
            incident_id="INC-001",
            alert_ids=["test_001"],
            root_cause_alert_id="test_001",
            participating_entities={"user": ["test@example.com"]},
            time_range={"start": datetime.now(), "end": datetime.now()},
            attack_techniques=["T1110"],
            confidence_score=0.9,
            recommended_action="Test action",
            hypothesis="Test hypothesis"
        )

        print("[PASS] Incident creation successful")
        print(f"  Incident ID: {incident.incident_id}")
        print(f"  Confidence: {incident.confidence_score}")

        return True
    except Exception as e:
        print(f"[FAIL] Schema creation failed: {e}")
        return False

def test_text_input():
    """Test text input processing"""
    print("\nTesting text input processing...")

    try:
        from ingestion.text_input import split_into_alert_chunks

        sample_text = """
        2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
        2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
        2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
        """

        chunks = split_into_alert_chunks(sample_text)

        print(f"[PASS] Text input processing successful")
        print(f"  Number of chunks: {len(chunks)}")

        for i, chunk in enumerate(chunks):
            print(f"  Chunk {i+1}: {chunk['raw_text'][:50]}...")

        return len(chunks) > 0
    except Exception as e:
        print(f"[FAIL] Text input processing failed: {e}")
        return False

def test_graph_build():
    """Test graph building with mock data"""
    print("\nTesting graph building...")

    try:
        from schema import Alert, AlertEntities
        from datetime import datetime
        from graph.build_graph import build_alert_entity_graph
        import networkx as nx

        # Create mock alerts
        alerts = [
            Alert(
                alert_id="alert_001",
                timestamp=datetime.now(),
                source_product="Identity Platform",
                alert_type="Failed login",
                severity="medium",
                entities=AlertEntities(user="j.suresh@acmecorp.com"),
                raw_text="2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com",
                mitre_technique="T1110"
            ),
            Alert(
                alert_id="alert_002",
                timestamp=datetime.now(),
                source_product="Identity Platform",
                alert_type="Successful login",
                severity="medium",
                entities=AlertEntities(user="j.suresh@acmecorp.com"),
                raw_text="2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com",
                mitre_technique="T1078"
            )
        ]

        # Build graph
        G = build_alert_entity_graph(alerts)

        print(f"[PASS] Graph building successful")
        print(f"  Nodes: {G.number_of_nodes()}")
        print(f"  Edges: {G.number_of_edges()}")

        return G.number_of_nodes() > 0 and G.number_of_edges() > 0
    except Exception as e:
        print(f"[FAIL] Graph building failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("Running basic functionality tests...\n")

    tests = [
        test_imports,
        test_schema_creation,
        test_text_input,
        test_graph_build
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("SUCCESS: All tests passed! The basic system is working.")
        return True
    else:
        print("FAILURE: Some tests failed. Please check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)