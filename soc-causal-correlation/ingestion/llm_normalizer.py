"""
LLM normalizer: calls Claude API to extract raw text -> Alert schema
"""

import os
import json
from typing import Dict, Any, Optional
from anthropic import Anthropic
from ..schema import Alert

class LLMPromptNormalizer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY must be provided")
        self.client = Anthropic(api_key=self.api_key)

    def normalize_alert(self, raw_text: str) -> Alert:
        """
        Use Claude to normalize raw alert text into structured Alert schema.

        Args:
            raw_text: Raw alert text from source

        Returns:
            Alert object with structured fields
        """
        prompt = f"""
        Extract structured information from the following security alert text.
        Return ONLY a valid JSON object with the following fields:
        - alert_id: string (generate if not present, use format "alert_{{timestamp}}_{{source}}")
        - timestamp: ISO 8601 format string (extract from text)
        - source_product: string (identity platform, EDR, firewall, etc.)
        - alert_type: string (brief description of alert type)
        - severity: string (low, medium, high, critical - infer from text)
        - entities: object with any of these fields if present: user, host, ip, process, file, cloud_role
        - raw_text: string (the original alert text)
        - mitre_technique: string (MITRE ATT&CK technique if mentioned, e.g., "T1110", null if not present)

        Alert text:
        {raw_text}

        JSON response:
        """

        try:
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Extract JSON from response
            json_text = response.content[0].text.strip()

            # Clean up potential markdown formatting
            if json_text.startswith("```json"):
                json_text = json_text[7:]
            if json_text.endswith("```"):
                json_text = json_text[:-3]

            alert_data = json.loads(json_text.strip())

            # Validate and create Alert object
            alert = Alert(**alert_data)
            return alert

        except Exception as e:
            # Fallback: create basic alert with raw text
            print(f"LLM normalization failed: {e}. Using fallback.")
            return Alert(
                alert_id=f"fallback_{hash(raw_text)}",
                timestamp=None,
                source_product="unknown",
                alert_type="unknown",
                severity="unknown",
                entities={},
                raw_text=raw_text,
                mitre_technique=None
            )

if __name__ == "__main__":
    # Test (requires API key)
    normalizer = LLMPromptNormalizer()
    sample_alert = "2023-01-15 09:14:02 Identity Platform: Five failed logins in 40 seconds for j.suresh@acmecorp.com"
    try:
        alert = normalizer.normalize_alert(sample_alert)
        print(alert.json())
    except Exception as e:
        print(f"Test failed (expected without API key): {e}")