import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Database Configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/soc_causal_correlation"
)
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))  # 1 hour
DB_ECHO = os.getenv("DB_ECHO", "false").lower() == "true"

# ML Configuration
ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", "./ml/models/")
ML_FEATURE_STORE_PATH = os.getenv("ML_FEATURE_STORE_PATH", "./ml/features/")
ENABLE_ML_ENHANCEMENT = os.getenv("ENABLE_ML_ENHANCEMENT", "true").lower() == "true"

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