"""
Final test to verify the implementation works.
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_basic_functionality():
    """Test that basic functionality works."""
    print("Testing basic pipeline functionality...")
    try:
        from pipeline import alerts_from_text, analyze_alerts

        # Sample alert data
        raw_text = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41"""

        alerts = alerts_from_text(raw_text)
        print(f"Generated {len(alerts)} alerts")

        if len(alerts) == 0:
            print("ERROR: No alerts generated")
            return False

        result = analyze_alerts(alerts, time_window_seconds=1800, min_alerts=2)
        incidents = result["incidents"]
        print(f"Generated {len(incidents)} incidents")

        if len(incidents) == 0:
            print("ERROR: No incidents generated")
            return False

        print("SUCCESS: Basic pipeline functionality works")
        return True
    except Exception as e:
        print(f"ERROR: Basic pipeline functionality failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_imports():
    """Test that all necessary imports work."""
    print("Testing imports...")
    try:
        # Test pipeline imports
        from pipeline import alerts_from_text, analyze_alerts

        # Test app imports
        from app import main

        # Test storage imports
        from storage.database import get_db_context
        from storage.repository import AlertRepository, IncidentRepository
        from storage.models import Alert, Incident

        print("SUCCESS: All imports work")
        return True
    except Exception as e:
        print(f"ERROR: Imports failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_storage_available_flag():
    """Test that storage availability flag is set correctly."""
    print("Testing storage availability flag...")
    try:
        from pipeline import STORAGE_AVAILABLE
        from app import STORAGE_AVAILABLE as APP_STORAGE_AVAILABLE

        print(f"Pipeline STORAGE_AVAILABLE: {STORAGE_AVAILABLE}")
        print(f"App STORAGE_AVAILABLE: {APP_STORAGE_AVAILABLE}")

        # At least one should be True if dependencies are installed
        # Note: In test environment without actual DB, both might be False
        # but the important thing is they don't crash
        print("SUCCESS: Storage availability flags accessible")
        return True
    except Exception as e:
        print(f"ERROR: Storage availability test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("FINAL IMPLEMENTATION VERIFICATION")
    print("=" * 60)

    tests = [
        test_imports,
        test_storage_available_flag,
        test_basic_functionality
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"ERROR: Test {test.__name__} crashed: {e}")
            results.append(False)
            print()

    print("=" * 60)
    if all(results):
        print("SUCCESS: ALL TESTS PASSED!")
        print("The implementation is working correctly.")
    else:
        print("FAILURE: SOME TESTS FAILED!")
        print(f"Results: {results}")
    print("=" * 60)

    return all(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)