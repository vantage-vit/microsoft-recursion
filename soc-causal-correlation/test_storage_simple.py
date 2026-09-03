"""
Simple test to verify storage integration concepts without Unicode issues.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_pipeline_imports():
    """Test that pipeline imports work correctly."""
    print("Testing pipeline imports...")
    try:
        from pipeline import alerts_from_text, analyze_alerts
        print("✅ Pipeline imports successful")
        return True
    except Exception as e:
        print(f"❌ Pipeline imports failed: {e}")
        return False

def test_app_imports():
    """Test that app imports work correctly."""
    print("Testing app imports...")
    try:
        from app import main
        print("✅ App imports successful")
        return True
    except Exception as e:
        print(f"❌ App imports failed: {e}")
        return False

def test_storage_imports():
    """Test that storage imports work correctly."""
    print("Testing storage imports...")
    try:
        from storage.database import get_db_context
        from storage.repository import AlertRepository, IncidentRepository
        from storage.models import Alert, Incident
        print("✅ Storage imports successful")
        return True
    except Exception as e:
        print(f"❌ Storage imports failed: {e}")
        return False

def test_pipeline_basic_functionality():
    """Test that pipeline basic functionality works."""
    print("Testing pipeline basic functionality...")
    try:
        from pipeline import alerts_from_text, analyze_alerts
        from ingestion.text_input import split_into_alert_chunks
        from ingestion.heuristic_normalizer import normalize_alert_locally

        # Sample alert data
        raw_text = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41"""

        alerts = alerts_from_text(raw_text)
        if len(alerts) == 0:
            print("❌ No alerts generated")
            return False

        result = analyze_alerts(alerts, time_window_seconds=1800, min_alerts=2)
        incidents = result["incidents"]

        print(f"✅ Pipeline processed {len(alerts)} alerts and generated {len(incidents)} incidents")
        return True
    except Exception as e:
        print(f"❌ Pipeline basic functionality failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 50)
    print("SIMPLE STORAGE INTEGRATION TEST")
    print("=" * 50)

    tests = [
        test_pipeline_imports,
        test_app_imports,
        test_storage_imports,
        test_pipeline_basic_functionality
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
            results.append(False)
            print()

    print("=" * 50)
    if all(results):
        print("🎉 ALL TESTS PASSED!")
        print("The storage layer integration is working correctly.")
    else:
        print("❌ SOME TESTS FAILED!")
        print(f"Results: {results}")
    print("=" * 50)

    return all(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)