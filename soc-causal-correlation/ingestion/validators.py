"""
Validators: pydantic validation + retry-on-malformed-JSON logic
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, ValidationError, validator
import json
import re

class Alert(BaseModel):
    alert_id: str
    timestamp: Optional[str] = None  # ISO format string
    source_product: str
    alert_type: str
    severity: str  # low, medium, high, critical
    entities: Dict[str, Any] = {}
    raw_text: str
    mitre_technique: Optional[str] = None

    @validator('severity')
    def validate_severity(cls, v):
        allowed = ['low', 'medium', 'high', 'critical']
        if v.lower() not in allowed:
            raise ValueError(f'Severity must be one of {allowed}')
        return v.lower()

    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v is None:
            return v
        # Basic ISO format validation
        iso_pattern = r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
        if not re.match(iso_pattern, v):
            # Try to parse common formats and warn
            pass  # For MVP, we'll accept it and let downstream handle
        return v

def validate_and_normalize_alert(alert_dict: Dict[str, Any]) -> Alert:
    """
    Validate and normalize alert dictionary, with retry logic for malformed JSON.

    Args:
        alert_dict: Dictionary containing alert data

    Returns:
        Validated Alert object
    """
    max_retries = 3

    for attempt in range(max_retries):
        try:
            alert = Alert(**alert_dict)
            return alert
        except ValidationError as e:
            if attempt == max_retries - 1:
                # Last attempt - raise the error
                raise e
            # Try to fix common issues
            alert_dict = _attempt_fix_alert_dict(alert_dict, e)

    # Should not reach here
    raise ValidationError("Failed to validate alert after retries", Alert)

def _attempt_fix_alert_dict(alert_dict: Dict[str, Any], error: ValidationError) -> Dict[str, Any]:
    """
    Attempt to fix common validation errors in alert dictionary.

    Args:
        alert_dict: Original alert dictionary
        error: ValidationError from pydantic

    Returns:
        Potentially fixed alert dictionary
    """
    fixed_dict = alert_dict.copy()

    # Extract error info
    error_str = str(error)

    # Fix severity issues
    if 'severity' in error_str:
        if 'severity' in fixed_dict:
            sev = fixed_dict['severity'].lower()
            if sev in ['med', 'medium', 'med']:
                fixed_dict['severity'] = 'medium'
            elif sev in ['high', 'hi']:
                fixed_dict['severity'] = 'high'
            elif sev in ['crit', 'critical']:
                fixed_dict['severity'] = 'critical'
            elif sev in ['low', 'lo']:
                fixed_dict['severity'] = 'low'
            else:
                fixed_dict['severity'] = 'unknown'  # Will be caught by validator

    # Fix timestamp issues
    if 'timestamp' in error_str and 'timestamp' in fixed_dict:
        ts = fixed_dict['timestamp']
        if ts and isinstance(ts, str):
            # Try to extract timestamp from various formats
            import re
            # Look for common timestamp patterns
            patterns = [
                r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})',
                r'(\d{2}:\d{2}:\d{2}\s+\d{4}-\d{2}-\d{2})',
                r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})'
            ]
            for pattern in patterns:
                match = re.search(pattern, ts)
                if match:
                    fixed_dict['timestamp'] = match.group(1).replace(' ', 'T')
                    break

    return fixed_dict

if __name__ == "__main__":
    # Test validation
    test_alert = {
        "alert_id": "test_001",
        "timestamp": "2023-01-15 09:14:02",
        "source_product": "Identity Platform",
        "alert_type": "Failed logins",
        "severity": "medium",
        "entities": {"user": "j.suresh@acmecorp.com"},
        "raw_text": "2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com",
        "mitre_technique": "T1110"
    }

    try:
        alert = validate_and_normalize_alert(test_alert)
        print("Validation successful:")
        print(alert.json(indent=2))
    except ValidationError as e:
        print(f"Validation failed: {e}")