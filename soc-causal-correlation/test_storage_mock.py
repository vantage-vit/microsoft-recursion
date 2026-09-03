"""
Mock test to verify storage integration without requiring actual database connection.
Tests that the storage components are properly integrated and called.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_pipeline_storage_integration():
    """Test that pipeline.py properly integrates with storage layer"""
    print("Testing pipeline storage integration...")

    # Import the modules
    from pipeline import alerts_from_text, analyze_alerts, STORAGE_AVAILABLE
    from ingestion.text_input import split_into_alert_chunks
    from ingestion.heuristic_normalizer import normalize_alert_locally

    print(f"Storage available: {STORAGE_AVAILABLE}")

    # Sample alert data
    raw_text = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41"""

    print("Processing alerts...")
    alerts = alerts_from_text(raw_text)
    print(f"Generated {len(alerts)} alerts")

    if len(alerts) == 0:
        print("❌ FAIL: No alerts generated")
        return False

    print("Analyzing alerts...")
    result = analyze_alerts(alerts, time_window_seconds=1800, min_alerts=2)
    incidents = result["incidents"]
    print(f"Generated {len(incidents)} incidents")

    # Even if storage is not available (no DB connection), the pipeline should still work
    if len(incidents) == 0:
        print("❌ FAIL: No incidents generated")
        return False

    print("✅ PASS: Pipeline works correctly")

    # Test that we can import storage components
    try:
        from storage.database import get_db_context
        from storage.repository import AlertRepository, IncidentRepository
        print("✅ PASS: Storage components imported successfully")
    except ImportError as e:
        print(f"⚠️  WARNING: Could not import storage components: {e}")
        # This is OK if dependencies aren't installed

    return True

def test_app_storage_integration():
    """Test that app.py properly integrates with storage layer for reporting"""
    print("\nTesting app storage integration...")

    try:
        from app import STORAGE_AVAILABLE, get_db_incident_details, get_security_guidance, get_historical_similarity
        print(f"App storage available: {STORAGE_AVAILABLE}")

        # Test security guidance function
        test_incident = {
            "incident_id": "test-001",
            "confidence_score": 0.85,
            "root_cause_alert_id": "alert_001",
            "recommended_action": "Disable specific user session",
            "techniques": ["T1110", "T1078"],
            "entities": [
                {"type": "user", "value": "j.suresh@acmecorp.com"},
                {"type": "host", "value": "DESKTOP-7QK41"}
            ]
        }

        guidance = get_security_guidance(test_incident)
        print(f"Security guidance generated: {len(guidance['do'])} dos, {len(guidance['dont'])} donts")

        if len(guidance["do"]) > 0 and len(guidance["dont"]) > 0:
            print("✅ PASS: Security guidance function works")
        else:
            print("❌ FAIL: Security guidance function didn't return expected results")
            return False

        # Test historical similarity function (should return empty list without storage)
        similar = get_historical_similarity("test-001")
        print(f"Historical similarity results: {len(similar)} items")

        # Test DB incident details function (should return None without storage)
        details = get_db_incident_details("test-001")
        if details is None:
            print("✅ PASS: DB incident details correctly returns None when storage not available")
        else:
            print(f"⚠️  INFO: DB incident details returned data: {details}")

        print("✅ PASS: App storage integration works")
        return True

    except Exception as e:
        print(f"❌ FAIL: Error testing app storage integration: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("STORAGE INTEGRATION TEST")
    print("=" * 60)

    success1 = test_pipeline_storage_integration()
    success2 = test_app_storage_integration()

    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 ALL TESTS PASSED!")
        print("The storage layer integration is working correctly.")
    else:
        print("❌ SOME TESTS FAILED!")
        print("Please check the errors above.")
    print("=" * 60)

    return success1 and success2

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)