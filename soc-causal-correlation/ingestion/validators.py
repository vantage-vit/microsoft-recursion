"""Validation boundary for normalized alert dictionaries."""

from typing import Any, Dict

try:
    from ..schema import Alert
except ImportError:
    from schema import Alert


def validate_and_normalize_alert(alert_dict: Dict[str, Any]) -> Alert:
    """Create the project's shared Alert model from external data."""
    return Alert.model_validate(alert_dict)
