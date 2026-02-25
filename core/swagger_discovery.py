"""Swagger/OpenAPI endpoint discovery utilities.

Discovery is intentionally lightweight and path-based: it probes a curated list
of common documentation endpoints and records responses that appear to be JSON.
"""

import requests

# Common paths observed across Swagger 2.0 and OpenAPI 3 deployments.
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
]


class SwaggerDiscovery:
    """Probe a base URL for likely API documentation endpoints."""

    def __init__(self, base_url: str):
        # Normalize trailing slash once so path concatenation stays consistent.
        self.base_url = base_url.rstrip("/")

    def discover(self) -> list[str]:
        """Return every documentation URL that responds as JSON."""
        print("\n[+] Starting Swagger discovery...\n")

        found: list[str] = []

        for path in COMMON_SWAGGER_PATHS:
            url = self.base_url + path

            try:
                response = requests.get(url, timeout=5)

                # `Content-Type` check avoids treating HTML docs/error pages as
                # machine-readable specs, which reduces noisy downstream parsing.
                if response.status_code == 200 and "json" in response.headers.get("Content-Type", ""):
                    print(f"[+] Found potential Swagger: {url}")
                    found.append(url)
                else:
                    print(f"[-] {url} -> {response.status_code}")

            except requests.RequestException:
                # Keep scanning on transient network/TLS/connection failures.
                print(f"[!] Error testing {url}")

        return found
