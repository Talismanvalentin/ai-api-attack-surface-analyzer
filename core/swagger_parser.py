"""Swagger/OpenAPI parsing helpers.

The parser converts the remote API specification into a normalized list of
`{method, path}` pairs consumed by the analyzer.
"""

import json

import requests


class SwaggerParser:
    """Fetch and parse a Swagger/OpenAPI JSON document."""

    def __init__(self, url: str):
        self.url = url
        self.swagger_data: dict | None = None

    def fetch_swagger(self) -> bool:
        """Download JSON spec and cache it in memory for later extraction."""
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            self.swagger_data = response.json()
            return True
        except requests.exceptions.RequestException as exc:
            print(f"[!] Error fetching Swagger: {exc}")
            return False
        except json.JSONDecodeError:
            print("[!] Response is not valid JSON.")
            return False

    def extract_endpoints(self) -> list[dict[str, str]]:
        """Extract endpoint path/method pairs from the `paths` section."""
        if not self.swagger_data:
            print("[!] No Swagger data loaded.")
            return []

        endpoints: list[dict[str, str]] = []
        paths = self.swagger_data.get("paths", {})

        for path, methods in paths.items():
            # Swagger path objects map HTTP verbs (get/post/...) to operation
            # metadata; only the verb keys are needed for attack-surface mapping.
            for method in methods.keys():
                endpoints.append(
                    {
                        "path": path,
                        "method": method.upper(),
                    }
                )

        return endpoints
