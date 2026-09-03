"""
Text input handler for MVP: split pasted text into alert chunks
"""

import re
from typing import List, Dict
from datetime import datetime

def split_into_alert_chunks(raw_text: str) -> List[Dict]:
    """
    Split raw pasted text into individual alert chunks.

    Args:
        raw_text: Raw text containing multiple alerts

    Returns:
        List of dictionaries, each representing an alert chunk
    """
    # Simple splitting by common alert separators
    # This is MVP - can be enhanced with more sophisticated parsing

    # Split by lines that look like alert separators (timestamps, etc.)
    lines = raw_text.strip().split('\n')

    alerts = []
    current_alert = []

    for line in lines:
        line = line.strip()
        if not line:
            if current_alert:
                alerts.append('\n'.join(current_alert))
                current_alert = []
            continue

        # Check if line starts a new alert (timestamp pattern)
        if re.match(r'^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line) or \
           re.match(r'^\d{2}:\d{2}:\d{2}', line):
            if current_alert:
                alerts.append('\n'.join(current_alert))
                current_alert = []
            current_alert.append(line)
        else:
            current_alert.append(line)

    if current_alert:
        alerts.append('\n'.join(current_alert))

    # Convert to alert chunk dictionaries
    alert_chunks = []
    for i, alert_text in enumerate(alerts):
        if alert_text.strip():
            alert_chunks.append({
                'alert_id': f'alert_{i}',
                'raw_text': alert_text,
                'timestamp': None,  # Will be extracted during normalization
                'chunk_index': i
            })

    return alert_chunks

if __name__ == "__main__":
    # Test the function
    sample_text = """
    2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com
    2023-01-15 09:16:40 Identity Platform: Successful login from unrecognized device for j.suresh@acmecorp.com
    2023-01-15 09:18:12 Endpoint (EDR): PowerShell spawned with encoded command on DESKTOP-7QK41
    """

    chunks = split_into_alert_chunks(sample_text)
    for chunk in chunks:
        print(f"Alert ID: {chunk['alert_id']}")
        print(f"Text: {chunk['raw_text'][:100]}...")
        print("---")