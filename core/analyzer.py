"""
Heuristic attack-surface analysis for parsed API endpoints.

This analyzer is intentionally rule-based and explainable.
Each signal is deterministic and later can be enriched by an LLM layer.
"""

import re
from typing import List, Dict, Any


class AttackSurfaceAnalyzer:
    """Apply lightweight security heuristics to endpoint metadata."""

    STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    IDENTIFIER_KEYWORDS = {
        "id",
        "user",
        "account",
        "org",
        "order",
        "tenant",
        "customer",
        "username",
        "email",
    }

    def __init__(self, endpoints: List[Dict[str, Any]]):
        self.endpoints = endpoints

    def enrich_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add structured risk signals to an endpoint.
        This does NOT classify vulnerabilities — it only emits structural signals.
        """

        signals: List[str] = []

        method = endpoint.get("method", "").upper()
        path = endpoint.get("path", "")
        parameters = endpoint.get("parameters", [])

        # 1️⃣ Detect state-changing methods
        if method in self.STATE_CHANGING_METHODS:
            signals.append("state_change")

        # 2️⃣ Detect object identifiers in path (e.g. /users/{id})
        dynamic_params = re.findall(r"\{(.*?)\}", path)

        for param in dynamic_params:
            if any(keyword in param.lower() for keyword in self.IDENTIFIER_KEYWORDS):
                signals.append("object_identifier")
                break

        # 3️⃣ Detect numeric inputs (potential unsafe handling)
        for param in parameters:
            param_type = param.get("type", "").lower()
            if param_type in {"number", "integer", "float"}:
                signals.append("numeric_input")
                break

        # 4️⃣ Detect admin-like routes
        if "admin" in path.lower():
            signals.append("admin_route")

        # 5️⃣ Detect authentication requirement (if provided by parser)
        if endpoint.get("auth_required"):
            signals.append("authenticated_endpoint")

        enriched = endpoint.copy()
        enriched["risk_signals"] = signals

        return enriched

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Return enriched endpoints with structural risk signals.
        No vulnerability classification is done here.
        """

        enriched_endpoints: List[Dict[str, Any]] = []

        for endpoint in self.endpoints:
            enriched = self.enrich_endpoint(endpoint)

            # Only keep endpoints that have signals
            if enriched["risk_signals"]:
                enriched_endpoints.append(enriched)

        return enriched_endpoints