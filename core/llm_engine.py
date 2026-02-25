"""
LLM engine for structured API security reasoning.

Uses OpenRouter-compatible API to:
1. Analyze endpoints individually.
2. Perform global pattern analysis.

Includes:
- Strict JSON enforcement
- Safe JSON extraction fallback
- HTTP error handling
- Deterministic low-temperature output
"""

import os
import json
import re
import requests
from typing import List, Dict, Any


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL_NAME = "openai/gpt-oss-120b"  # Cambiar si quieres otro modelo


class LLMEngine:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")

        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set in environment.")

    # --------------------------
    # INTERNAL SAFE JSON PARSER
    # --------------------------

    def _safe_json_parse(self, text: str) -> Dict[str, Any]:
        """
        Attempts strict JSON parsing.
        If it fails, extracts first JSON object via regex.
        """
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    return {
                        "error": "Malformed JSON from model",
                        "raw": text,
                    }
            return {
                "error": "No JSON object detected",
                "raw": text,
            }

    # --------------------------
    # CORE MODEL CALL
    # --------------------------

    def _call_model(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "temperature": 0.2,  # Low temperature for deterministic output
        }

        try:
            response = requests.post(
                OPENROUTER_URL,
                headers=headers,
                json=payload,
                timeout=60,
            )

            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]

            return self._safe_json_parse(content)

        except requests.exceptions.RequestException as exc:
            return {
                "error": f"HTTP request failed: {str(exc)}"
            }

        except Exception as exc:
            return {
                "error": f"Unexpected error: {str(exc)}"
            }

    # --------------------------
    # PHASE 1 – ENDPOINT LEVEL
    # --------------------------

    def analyze_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """
You are a senior API security researcher.

Analyze the given endpoint structure.

Rules:
- Do NOT invent vulnerabilities.
- Base reasoning only on provided structure.
- Do NOT include explanations outside JSON.
- Respond ONLY with valid JSON.

Return exactly:

{
  "vulnerability_class": "string",
  "risk_level": "Low|Medium|High",
  "reasoning": "string",
  "conceptual_test_idea": "string"
}
"""

        user_prompt = f"""
Endpoint data:
{json.dumps(endpoint, indent=2)}
"""

        messages = [
            {"role": "system", "content": system_prompt.strip()},
            {"role": "user", "content": user_prompt.strip()},
        ]

        return self._call_model(messages)

    # --------------------------
    # PHASE 2 – GLOBAL ANALYSIS
    # --------------------------

    def analyze_global(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        system_prompt = """
You are a senior API security researcher.

Analyze the entire API surface holistically.

Look for:
- Systemic access control weaknesses
- Privilege separation issues
- Abuse chains
- Structural anti-patterns

Do NOT invent implementation details.
Respond ONLY with valid JSON.

Return exactly:

{
  "systemic_risks": "string",
  "privilege_patterns": "string",
  "abuse_chains": "string",
  "overall_risk_assessment": "Low|Medium|High"
}
"""

        user_prompt = f"""
API Surface:
{json.dumps(endpoints, indent=2)}
"""

        messages = [
            {"role": "system", "content": system_prompt.strip()},
            {"role": "user", "content": user_prompt.strip()},
        ]

        return self._call_model(messages)