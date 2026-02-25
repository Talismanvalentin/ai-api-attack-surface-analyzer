"""
Swagger/OpenAPI parsing helpers.

Parses a remote Swagger/OpenAPI JSON spec into normalized endpoint objects
including parameters, request body fields, and authentication metadata.
"""

import os
import json
import requests
import urllib3
from typing import List, Dict, Any


class SwaggerParser:
    """Fetch and parse a Swagger/OpenAPI JSON document."""

    def __init__(self, url: str):
        self.url = url
        self.swagger_data: Dict[str, Any] | None = None

    def fetch_swagger(self) -> bool:
        """Download JSON spec and cache it in memory."""
        try:
            # Enable insecure mode only for lab environments
            htb_mode = os.getenv("HTB_MODE", "0") == "1"

            if htb_mode:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(
                self.url,
                timeout=10,
                verify=not htb_mode,
            )

            response.raise_for_status()
            self.swagger_data = response.json()
            return True

        except requests.exceptions.RequestException as exc:
            print(f"[!] Error fetching Swagger: {exc}")
            return False

        except ValueError:
            print("[!] Response is not valid JSON.")
            return False

    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """Extract structured endpoint metadata from the spec."""
        if not self.swagger_data:
            print("[!] No Swagger data loaded.")
            return []

        endpoints: List[Dict[str, Any]] = []

        paths = self.swagger_data.get("paths", {})
        global_security = self.swagger_data.get("security")

        for path, methods in paths.items():
            for method, details in methods.items():

                if method.lower() not in {
                    "get", "post", "put", "patch", "delete", "options", "head"
                }:
                    continue

                endpoint: Dict[str, Any] = {
                    "path": path,
                    "method": method.upper(),
                    "parameters": [],
                    "auth_required": bool(details.get("security", global_security)),
                    "description": details.get("description", "")
                }

                # 1️⃣ Path + Query Parameters
                for param in details.get("parameters", []):
                    endpoint["parameters"].append(
                        {
                            "name": param.get("name"),
                            "in": param.get("in"),
                            "type": param.get("schema", {}).get("type", "unknown"),
                            "required": param.get("required", False),
                        }
                    )

                # 2️⃣ Request Body (OpenAPI 3)
                request_body = details.get("requestBody")
                if request_body:
                    content = request_body.get("content", {})

                    for media_type in content.values():
                        schema = media_type.get("schema", {})
                        properties = schema.get("properties", {})

                        for prop_name, prop_details in properties.items():
                            endpoint["parameters"].append(
                                {
                                    "name": prop_name,
                                    "in": "body",
                                    "type": prop_details.get("type", "unknown"),
                                    "required": prop_name in schema.get("required", []),
                                }
                            )

                endpoints.append(endpoint)

        return endpoints