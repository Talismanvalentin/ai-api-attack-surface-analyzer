"""
Swagger/OpenAPI discovery engine.

Attempts to locate Swagger/OpenAPI documentation across common paths.
"""

import requests
from urllib.parse import urljoin


COMMON_SWAGGER_PATHS = [
    "/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/docs",
    "/api/docs",
    "/.well-known/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/api/v1/swagger.json",
    "/api/",
]


class SwaggerDiscovery:
    def __init__(self, base_url: str):
        # Normalize base URL once
        self.base_url = base_url.rstrip("/") + "/"

    def discover(self) -> str | None:
        """
        Try common Swagger paths and return first valid JSON spec URL.
        """

        print("\n[+] Starting Swagger discovery...\n")

        for path in COMMON_SWAGGER_PATHS:
            full_url = urljoin(self.base_url, path.lstrip("/"))

            try:
                response = requests.get(
                    full_url,
                    timeout=5,
                    verify=False  # Required for HTB self-signed certs
                )

                if response.status_code == 200:
                    # Check if it looks like a Swagger/OpenAPI spec
                    content_type = response.headers.get("Content-Type", "")
                    if "json" in content_type.lower():
                        try:
                            data = response.json()

                            # Minimal validation: must contain "paths"
                            if "paths" in data:
                                print(f"[+] Found Swagger at: {full_url}")
                                return full_url

                        except ValueError:
                            continue

                print(f"[!] Tested: {full_url} (not valid Swagger)")

            except requests.RequestException:
                print(f"[!] Error testing {full_url}")

        print("[!] No Swagger documentation found.")
        return None