# Alert Persistence & Configuration Guide
## How to Save Input Alert Fields for Later Analysis

This document explains how to configure the SOC Causal Correlation system to save alert inputs and outputs for audit, compliance, and ongoing security improvement.

### Current Default Behavior
By default, the system:
1. Accepts alert input via clipboard/paste in the Streamlit interface
2. Processes alerts in memory
3. Displays results but does not automatically save inputs or outputs
4. Requires manual export of results for record keeping

### Recommended Configuration for Alert Persistence

#### Option 1: Enhanced Streamlit Interface (Recommended for Small Businesses)
Modify `app.py` to automatically save alert sessions:

```python
# Add these imports to app.py
import json
from datetime import datetime
import os

# Add this function to app.py
def save_alert_session(raw_text, result, session_id=None):
    """Save alert input and analysis results to disk"""
    if session_id is None:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create sessions directory if it doesn't exist
    sessions_dir = "alert_sessions"
    os.makedirs(sessions_dir, exist_ok=True)
    
    session_data = {
        "session_id": session_id,
        "timestamp": datetime.now().isoformat(),
        "raw_input": raw_text,
        "input_alerts_count": len(result.get("alerts", [])) if "alerts" in result else 0,
        "incidents_found": len(result.get("incidents", [])) if "incidents" in result else 0,
        "result_summary": {
            k: v for k, v in result.items() 
            if k not in ["graph"]  # Skip non-serializable objects
        }
    }
    
    filepath = os.path.join(sessions_dir, f"session_{session_id}.json")
    with open(filepath, 'w') as f:
        json.dump(session_data, f, indent=2, default=str)
    
    return filepath

# Then modify the analysis section in app.py:
if analyze:
    alerts = alerts_from_text(raw_text)
    if not alerts:
        st.warning("No timestamped alert lines were found. Add one alert per line.")
        return
    
    result = analyze_alerts(alerts, time_window * 60, int(min_alerts))
    
    # AUTO-SAVE SESSION
    session_file = save_alert_session(raw_text, result)
    st.success(f"Session saved to: {session_file}")
    
    # ... rest of existing display code ...
```

#### Option 2: Command Line Usage with Automatic Logging
For users comfortable with command line, modify `pipeline.py`:

```python
# Add to pipeline.py
import json
import os
from datetime import datetime

def alerts_from_text_with_logging(raw_text, log_dir="alert_logs"):
    """Version that automatically logs inputs and outputs"""
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"alerts_{timestamp}.txt")
    result_file = os.path.join(log_dir, f"result_{timestamp}.json")
    
    # Save raw input
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(raw_text)
    
    # Process alerts
    alerts = alerts_from_text(raw_text)
    result = analyze_alerts(alerts)
    
    # Save result (excluding non-serializable graph object)
    result_to_save = result.copy()
    if 'graph' in result_to_save:
        del result_to_save['graph']  # NetworkX graph not JSON serializable
    
    with open(result_file, 'w') as f:
        json.dump(result_to_save, f, indent=2, default=str)
    
    print(f"Alerts logged to: {log_file}")
    print(f"Results saved to: {result_file}")
    
    return result

# Then expose this function in the module's __init__.py or create a CLI wrapper
```

#### Option 3: Environment-Based Configuration
Add to `config.py`:

```python
# Alert Persistence Settings
ALERT_PERSISTENCE_ENABLED = os.getenv("ALERT_PERSISTENCE_ENABLED", "true").lower() == "true"
ALERT_STORAGE_PATH = os.getenv("ALERT_STORAGE_PATH", "./alert_archive")
ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", "90"))
AUTO_EXPORT_RESULTS = os.getenv("AUTO_EXPORT_RESULTS", "true").lower() == "true"

# Create storage directory on import
if ALERT_PERSISTENCE_ENABLED:
    os.makedirs(ALERT_STORAGE_PATH, exist_ok=True)
```

### Directory Structure for Alert Archives

Recommended folder structure:
```
soc-alerts-archive/
├── raw_inputs/                 # Original alert text inputs
│   ├── 2026/
│   │   ├── 09/
│   │   │   ├── 03/
│   │   │   │   ├── alerts_20260903_214157.txt
│   │   │   │   └── ...
├── processed_results/          # Analysis outputs (JSON)
│   ├── 2026/
│   │   ├── 09/
│   │   │   ├── 03/
│   │   │   │   ├── result_20260903_214157.json
│   │   │   │   └── ...
├── incidents/                  # Confirmed incidents for investigation
│   ├── 2026/
│   │   ├── 09/
│   │   │   ├── 03/
│   │   │   │   ├── incident_INC-001_20260903_214157.json
│   │   │   │   └── ...
├── exports/                    # Manual exports for sharing/compliance
│   ├── monthly_reports/
│   ├── compliance_submissions/
│   └── forensic_packages/
└── index.json                  # Master index of all archived sessions
```

### Automated Maintenance Script
Create `maintain_alert_archive.py`:

```python
#!/usr/bin/env python3
"""
Automated maintenance for alert archive:
- Compress old files
- Delete data beyond retention period
- Generate monthly indexes
"""

import os
import json
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import path

def compress_old_files(directory, days_old=30):
    """Compress files older than specified days"""
    cutoff = datetime.now() - timedelta(days=days_old)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if file_time < cutoff and not filepath.endswith('.gz'):
                with open(filepath, 'rb') as f_in:
                    with gzip.open(filepath + '.gz', 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(filepath)
                print(f"Compressed: {filepath}")

def enforce_retention_policy(directory, retention_days):
    """Delete files beyond retention period"""
    cutoff = datetime.now() - timedelta(days=retention_days)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if file_time < cutoff:
                os.remove(filepath)
                print(f"Deleted (retention): {filepath}")

def generate_monthly_index(archive_root, output_file):
    """Create index of all archived sessions"""
    index = {
        "generated": datetime.now().isoformat(),
        "sessions": [],
        "total_sessions": 0
    }
    
    for root, dirs, files in os.walk(archive_root):
        for file in files:
            if file.endswith('.json') and ('result_' in file or 'session_' in file):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    index["sessions"].append({
                        "file": filepath,
                        "timestamp": data.get("timestamp", "unknown"),
                        "session_id": data.get("session_id", "unknown"),
                        "alert_count": data.get("input_alerts_count", 0),
                        "incidents_found": data.get("incidents_found", 0)
                    })
                except:
                    pass  # Skip corrupted files
    
    index["total_sessions"] = len(index["sessions"])
    
    with open(output_file, 'w') as f:
        json.dump(index, f, indent=2)
    
    print(f"Index generated: {output_file} with {index['total_sessions']} sessions")

if __name__ == "__main__":
    ARCHIVE_ROOT = "./alert_archive"
    
    print("Starting alert archive maintenance...")
    compress_old_files(ARCHIVE_ROOT, days_old=30)
    enforce_retention_policy(ARCHIVE_ROOT, retention_days=90)
    generate_monthly_index(
        ARCHIVE_ROOT, 
        f"{ARCHIVE_ROOT}/index_{datetime.now().strftime('%Y%m')}.json"
    )
    print("Maintenance complete.")
```

### Export Formats for Different Purposes

#### 1. Compliance Export (JSON)
```json
{
  "export_metadata": {
    "export_timestamp": "2026-09-04T10:30:00Z",
    "export_purpose": "SOC 2 Type II - Monitoring Evidence",
    "date_range": {
      "start": "2026-08-01",
      "end": "2026-08-31"
    },
    "system_version": "SOC Causal Correlation v1.0-MVP"
  },
  "alert_summary": {
    "total_alerts_processed": 1245,
    "total_incidents_identified": 23,
    "high_confidence_incidents": 8,
    "average_alerts_per_incident": 54.1
  },
  "incidents": [
    {
      "incident_id": "INC-20260815-001",
      "timestamp": "2026-08-15T14:22:00Z",
      "alert_count": 7,
      "confidence_score": 0.92,
      "root_cause": "alert_20260815_142203",
      "recommended_action": "Disable specific user session and force password reset",
      "techniques": ["T1078", "T1110", "T1041"],
      "participating_entities": {
        "user": ["j.suresh@company.com"],
        "host": ["WKS-DEV-045"],
        "cloud_role": ["arn:aws:iam::role/dev-access"]
      }
    }
  ]
}
```

#### 2. Executive Summary (Markdown/PDF)
Create automated reports showing:
- Trend charts: alerts per week before/after correlation
- Incident heatmap by time of day
- Top 5 root causes
- Response action effectiveness
- Security posture score over time

#### 3. Forensic Package (ZIP Archive)
For law enforcement or insurance claims:
- All original alert inputs (timestamps preserved)
- Complete analysis chain (inputs → processing → outputs)
- System version and configuration used
- Analyst notes and actions taken
- Hash verification files for integrity

### Implementation Checklist for Alert Persistence

#### Phase 1: Basic Logging (1-2 hours)
- [ ] Choose persistence method (Option 1, 2, or 3 above)
- [ ] Implement basic input/output saving
- [ ] Test with sample alert data
- [ ] Verify files are saved correctly and readable

#### Phase 2: Organization & Retention (2-4 hours)
- [ ] Implement directory structure
- [ ] Create automated maintenance script
- [ ] Set up scheduled execution (Windows Task Scheduler/cron)
- [ ] Test retention and compression policies

#### Phase 3: Reporting & Export (3-5 hours)
- [ ] Implement export functions for compliance formats
- [ ] Create automated report generation
- [ ] Set up secure storage for exported reports
- [ ] Test export/restore procedures

#### Phase 4: Advanced Features (Optional)
- [ ] Implement alert deduplication in storage
- [ ] Add encryption for sensitive alert data
- [ ] Create web interface for browsing alert history
- [ ] Integrate with SIEM for long-term archival

### Best Practices for Alert Data Management

#### Data Privacy & Security
- Store alert archives in access-controlled locations
- Consider encrypting files containing sensitive data (PII, credentials)
- Implement role-based access to alert archives
- Log all access to alert data for audit purposes

#### Data Quality
- Validate alert format at ingest time
- Maintain original timestamp fidelity
- Track data completeness metrics
- Regularly sample archived data for integrity checks

#### Operational Considerations
- Monitor storage usage and set up alerts at 80% capacity
- Test restore procedures quarterly
- Document archive procedures for business continuity
- Consider off-site backup for critical alert data

### Troubleshooting Common Issues

#### Problem: "No space left on device"
Solution: 
- Run compression script more frequently
- Reduce retention period for debug/verbose logs
- Implement alert sampling for high-volume periods

#### Problem: "Cannot read saved alert file"
Solution:
- Check file permissions
- Verify file is not corrupted (try opening with text editor)
- Ensure you're using the correct encoding (UTF-8 recommended)
- Check if file was compressed and needs decompression first

#### Problem: "Missing alerts in historical analysis"
Solution:
- Verify collection script is running for all sources
- Check time zone consistency across systems
- Look for gaps in collection timestamps
- Validate that alert sources haven't changed format

### Cost Estimates for Alert Persistence

#### Storage Requirements (Example: 100 alerts/day)
- Daily: ~500KB raw + ~200KB processed = ~700KB/day
- Monthly: ~21MB
- Yearly: ~250MB
- 5-year archive: ~1.25GB (very manageable on modern systems)

#### Time Investment
- Initial setup: 4-8 hours
- Weekly maintenance: <15 minutes (mostly automated)
- Monthly review: 30-60 minutes
- Annual deep dive: 2-4 hours

#### Tools Required
- None beyond what's already in the system
- Uses standard Python libraries (json, os, datetime, gzip, shutil)
- No additional cost for basic implementation

### Conclusion
Implementing alert persistence transforms the SOC Causal Correlation system from a real-time analysis tool into a comprehensive security intelligence platform. By saving inputs and outputs, organizations gain:

1. **Audit Trail**: Complete evidence for compliance and investigations
2. **Trend Analysis**: Ability to measure security effectiveness over time
3. **Knowledge Base**: Historical incidents for training and reference
4. **Process Improvement**: Data-driven refinement of detection and response
5. **Legal Protection**: Demonstrated due diligence in security monitoring

The initial investment of a few hours pays dividends through improved security posture, reduced investigation time, and enhanced ability to demonstrate security value to stakeholders.

---
*Based on analysis of SOC Causal Correlation system and intended for use with output from: "C:\Users\Adhvai\Videos\Captures\SOC Causal Correlation - Brave 2026-09-03 21-41-57.mp4"*