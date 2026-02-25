"""Heuristic attack-surface analysis for parsed API endpoints.

This analyzer is intentionally rule-based and explainable: each finding maps to
clear string rules that security testers can validate manually.
"""

import re


class AttackSurfaceAnalyzer:
    """Apply lightweight security heuristics to endpoint metadata."""

    def __init__(self, endpoints: list[dict[str, str]]):
        self.endpoints = endpoints

    def analyze(self) -> list[dict[str, str | list[str]]]:
        """Return findings with severity and human-readable risk reasons."""
        findings: list[dict[str, str | list[str]]] = []

        for endpoint in self.endpoints:
            path = endpoint["path"]
            method = endpoint["method"]

            risks: list[str] = []
            severity = "LOW"

            # Parameter names matching these tokens often indicate object/user
            # references where authorization mistakes can create BOLA/IDOR risk.
            id_patterns = [
                "id",
                "user",
                "account",
                "org",
                "order",
                "tenant",
                "customer",
                "username",
                "email",
            ]

            dynamic_params = re.findall(r"\{(.*?)\}", path)

            for param in dynamic_params:
                if any(keyword in param.lower() for keyword in id_patterns):
                    risks.append(f"Sensitive identifier in path: {param}")
                    severity = "HIGH"

            # Stateful methods can mutate or delete resources and typically need
            # stronger authn/authz and anti-abuse controls than pure reads.
            if method in ["DELETE", "PUT", "PATCH"]:
                risks.append("State-changing method (authorization check required)")
                severity = "HIGH"

            # Admin path segments are strong indicators of privileged operations.
            if "admin" in path.lower():
                risks.append("Administrative endpoint detected")
                severity = "HIGH"

            if risks:
                findings.append(
                    {
                        "path": path,
                        "method": method,
                        "severity": severity,
                        "risks": risks,
                    }
                )

        return findings
