"""
Test script to verify that the storage layer works correctly with the pipeline.
"""

import os
import sys
from datetime import datetime

# Set up the database URL for testing (if not already set)
if "DATABASE_URL" not in os.environ:
    # Use a default for testing - adjust as needed
    os.environ["DATABASE_URL"] = "postgresql://postgres:password@localhost:5432/soc_causal_correlation_test"

# Now import the modules
from pipeline import alerts_from_text, analyze_alerts
from storage.database import get_engine, init_database, check_database_connection
from storage.repository import AlertRepository, IncidentRepository
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

def test_storage():
    print("Testing storage layer with pipeline...")

    # Check database connection
    if not check_database_connection():
        print("ERROR: Cannot connect to database. Please check your PostgreSQL connection and DATABASE_URL.")
        return False

    # Initialize database (create tables)
    print("Initializing database...")
    init_database()

    # Sample alert data
    raw_text = """2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
2023-01-15 09:24:55 Cloud (AWS): New cloud role assumed - arn:aws:iam::role/finance-read
2023-01-15 09:41:03 Firewall: Outbound transfer - 2.3GB to unrecognized IP 203.0.113.44"""

    print("Processing alerts...")
    alerts = alerts_from_text(raw_text)
    print(f"Generated {len(alerts)} alerts")

    print("Analyzing alerts...")
    result = analyze_alerts(alerts, time_window_seconds=1800, min_alerts=2)
    incidents = result["incidents"]
    print(f"Generated {len(incidents)} incidents")

    # Now verify storage
    print("Verifying storage...")
    engine = get_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    try:
        # Check alerts
        alert_repo = AlertRepository()
        stored_alerts = alert_repo.get_recent_alerts(db, limit=10)
        print(f"Found {len(stored_alerts)} alerts in database")
        for alert in stored_alerts:
            print(f"  Alert ID: {alert.alert_id}, Source: {alert.source_product}, Severity: {alert.severity}")

        # Check incidents
        incident_repo = IncidentRepository()
        stored_incidents = incident_repo.get_recent_incidents(db, limit=10)
        print(f"Found {len(stored_incidents)} incidents in database")
        for incident in stored_incidents:
            print(f"  Incident ID: {incident.incident_id}, Confidence: {incident.confidence_score}")
            print(f"    Alert IDs: {[alert.alert_id for alert in incident.alerts]}")
            print(f"    Techniques: {[t.technique for t in incident.techniques]}")
            entities_list = [(e.entity_type, e.entity_value) for e in incident.entities]
            print(f"    Entities: {entities_list}")

        # Verify that the number of alerts and incidents matches what we expect
        if len(stored_alerts) >= len(alerts):
            print("✅ Alerts storage: PASS")
        else:
            print("❌ Alerts storage: FAIL - Expected at least {}, got {}".format(len(alerts), len(stored_alerts)))
            return False

        if len(stored_incidents) >= len(incidents):
            print("✅ Incidents storage: PASS")
        else:
            print("❌ Incidents storage: FAIL - Expected at least {}, got {}".format(len(incidents), len(stored_incidents)))
            return False

        # Check relationships
        if stored_incidents:
            incident = stored_incidents[0]
            if len(incident.alerts) > 0:
                print("✅ Incident-Alert relationship: PASS")
            else:
                print("❌ Incident-Alert relationship: FAIL - No alerts linked to incident")
                return False

            if len(incident.techniques) > 0 or len(incident.entities) > 0:
                print("✠ Incident-Techniques/Entities relationship: PASS")
            else:
                print("⚠️  Incident-Techniques/Entities relationship: WARNING - No techniques or entities linked (may be expected if none extracted)")

        print("\n🎉 All tests passed!")
        return True

    except Exception as e:
        print(f"❌ Error during verification: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = test_storage()
    sys.exit(0 if success else 1)