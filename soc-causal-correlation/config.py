import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Time window thresholds (seconds)
TIME_WINDOW_SECONDS = 1800  # 30 minutes

# Severity weights
SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

# Other constants
MIN_ALERTS_FOR_INCIDENT = 2