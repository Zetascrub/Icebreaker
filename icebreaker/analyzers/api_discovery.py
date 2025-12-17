"""
API endpoint discovery analyzer.
"""
from __future__ import annotations
import httpx
import json
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from icebreaker.core.models import RunContext, Service, Finding


class APIDiscovery:
    """Icebreaker analyzer for API endpoint discovery."""

    id = "api_discovery"
    consumes = ["service:http", "service:https"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        """
        Discover API endpoints for a service.

        Args:
            ctx: Run context
            service: Service to analyze

        Returns:
            List of findings
        """
        findings = []
        analyzer = APIDiscoveryAnalyzer()

        try:
            use_https = service.name == "https" or service.port == 443
            result = analyzer.analyze(service.target, service.port, use_https)

            for finding_dict in result.get("findings", []):
                findings.append(Finding(
                    id=f"api_discovery.{finding_dict.get('category', 'misc')}.{service.target}.{service.port}",
                    title=finding_dict["title"],
                    severity=finding_dict["severity"].upper(),
                    target=service.target,
                    port=service.port,
                    tags=["api", finding_dict.get("category", "endpoints")],
                    details={
                        "description": finding_dict["description"],
                        "endpoints": result.get("api_endpoints", []),
                        "documentation": result.get("documentation_found", [])
                    },
                    recommendation=finding_dict.get("recommendation")
                ))

            analyzer.close()

        except Exception as e:
            # Silently skip if analysis fails
            pass

        return findings


class APIDiscoveryAnalyzer:
    """Analyzer for discovering API endpoints."""

    COMMON_API_PATHS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/rest",
        "/graphql",
        "/swagger",
        "/swagger.json",
        "/swagger.yml",
        "/openapi.json",
        "/api-docs",
        "/api/docs",
        "/api/swagger",
        "/api/swagger.json",
        "/api/openapi.json",
        "/.well-known/openapi",
        "/redoc",
        "/docs",
        "/documentation",
        "/actuator",
        "/health",
        "/status",
        "/metrics",
        "/info",
    ]

    COMMON_API_ENDPOINTS = [
        "/users",
        "/user",
        "/auth",
        "/login",
        "/logout",
        "/register",
        "/token",
        "/refresh",
        "/admin",
        "/config",
        "/settings",
        "/profile",
        "/account",
        "/password",
        "/reset",
        "/upload",
        "/download",
        "/files",
        "/search",
        "/data",
        "/items",
        "/products",
        "/orders",
    ]

    def __init__(self):
        self.client = httpx.Client(timeout=10.0, follow_redirects=True)
        self.discovered_endpoints: Set[str] = set()

    def analyze(self, target: str, port: int = 80, use_https: bool = False) -> Dict[str, Any]:
        """
        Discover API endpoints on a target.

        Args:
            target: Target hostname or IP
            port: Target port
            use_https: Whether to use HTTPS

        Returns:
            Dictionary with discovered API endpoints and findings
        """
        findings = []
        result = {
            "target": target,
            "port": port,
            "api_endpoints": [],
            "documentation_found": [],
            "findings": findings
        }

        protocol = "https" if use_https or port == 443 else "http"
        base_url = f"{protocol}://{target}:{port}"

        # Check common API paths
        for path in self.COMMON_API_PATHS:
            url = urljoin(base_url, path)
            try:
                response = self.client.get(url)
                if response.status_code < 400:
                    content = response.text
                    content_length = len(content)

                    # Validate this is a real response, not a generic error page
                    # Real API endpoints should have substantial content
                    if content_length < 100:
                        continue

                    # Check if it's just a generic "200 OK" page
                    if "<center>200 ok</center>" in content.lower():
                        continue

                    self.discovered_endpoints.add(path)

                    # Check if it's documentation
                    if any(doc in path.lower() for doc in ['swagger', 'openapi', 'docs', 'redoc']):
                        # Validate it's actually API documentation
                        content_lower = content.lower()
                        is_api_docs = (
                            "swagger" in content_lower or
                            "openapi" in content_lower or
                            '"openapi"' in content or
                            '"swagger"' in content or
                            "api" in content_lower and ("endpoint" in content_lower or "schema" in content_lower)
                        )

                        if is_api_docs:
                            result["documentation_found"].append({
                                "path": path,
                                "status_code": response.status_code,
                                "content_type": response.headers.get("content-type", ""),
                                "content_length": content_length
                            })

                            findings.append({
                                "title": "API Documentation Exposed",
                                "severity": "low",
                                "description": f"API documentation found at: {path}",
                                "recommendation": "Ensure API documentation doesn't expose sensitive information. "
                                                 "Consider restricting access in production.",
                                "category": "api"
                            })
                    else:
                        result["api_endpoints"].append({
                            "path": path,
                            "status_code": response.status_code,
                            "content_type": response.headers.get("content-type", ""),
                            "content_length": content_length
                        })
            except Exception:
                continue

        # Try to find specific API endpoints under discovered paths
        for base_path in list(self.discovered_endpoints):
            if 'docs' not in base_path and 'swagger' not in base_path:
                for endpoint in self.COMMON_API_ENDPOINTS:
                    full_path = f"{base_path}{endpoint}"
                    url = urljoin(base_url, full_path)
                    try:
                        response = self.client.head(url, timeout=5.0)
                        if response.status_code < 400:
                            result["api_endpoints"].append({
                                "path": full_path,
                                "status_code": response.status_code,
                                "methods_allowed": response.headers.get("allow", "")
                            })
                    except Exception:
                        continue

        # Check for GraphQL
        graphql_path = "/graphql"
        try:
            graphql_url = urljoin(base_url, graphql_path)
            # Try introspection query
            introspection_query = {
                "query": "{ __schema { types { name } } }"
            }
            response = self.client.post(
                graphql_url,
                json=introspection_query,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "__schema" in str(data):
                        findings.append({
                            "title": "GraphQL Introspection Enabled",
                            "severity": "medium",
                            "description": "GraphQL introspection is enabled, exposing the entire schema.",
                            "recommendation": "Disable GraphQL introspection in production environments.",
                            "category": "api"
                        })

                        result["api_endpoints"].append({
                            "path": graphql_path,
                            "status_code": response.status_code,
                            "type": "graphql",
                            "introspection_enabled": True
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # Check for unauthenticated admin endpoints
        admin_paths = ["/admin", "/api/admin", "/admin/api"]
        for admin_path in admin_paths:
            url = urljoin(base_url, admin_path)
            try:
                response = self.client.get(url)
                if response.status_code in [200, 301, 302]:
                    content = response.text

                    # Validate it's not a generic 200 OK page
                    if len(content) < 100 or "<center>200 ok</center>" in content.lower():
                        continue

                    # Check if it looks like an actual admin panel
                    content_lower = content.lower()
                    is_admin = (
                        "admin" in content_lower or
                        "dashboard" in content_lower or
                        "login" in content_lower and "admin" in content_lower or
                        "management" in content_lower
                    )

                    if is_admin:
                        findings.append({
                            "title": "Potential Admin Endpoint Accessible",
                            "severity": "high",
                            "description": f"Admin endpoint at {admin_path} returned status {response.status_code}.",
                            "recommendation": "Ensure admin endpoints require strong authentication.",
                            "category": "api"
                        })
            except Exception:
                continue

        # Check for debug endpoints
        debug_paths = ["/debug", "/api/debug", "/.env", "/config.json"]
        for debug_path in debug_paths:
            url = urljoin(base_url, debug_path)
            try:
                response = self.client.get(url)
                if response.status_code == 200:
                    content = response.text

                    # Validate it's not a generic 200 OK page
                    if len(content) < 100 or "<center>200 ok</center>" in content.lower():
                        continue

                    # For .env and config.json, use strict validation
                    if debug_path in ["/.env", "/config.json"]:
                        if debug_path == "/.env":
                            # .env files should have KEY=VALUE format
                            if "=" not in content or "<html" in content.lower():
                                continue
                        elif debug_path == "/config.json":
                            # Should be valid JSON
                            if not content.strip().startswith("{"):
                                continue

                    findings.append({
                        "title": "Debug Endpoint Exposed",
                        "severity": "high",
                        "description": f"Debug endpoint found at: {debug_path}",
                        "recommendation": "Remove or restrict access to debug endpoints in production.",
                        "category": "api"
                    })
            except Exception:
                continue

        # Summary finding
        if result["api_endpoints"]:
            findings.append({
                "title": f"Discovered {len(result['api_endpoints'])} API Endpoints",
                "severity": "info",
                "description": f"Found {len(result['api_endpoints'])} accessible API endpoints.",
                "recommendation": "Review all discovered endpoints and ensure proper authentication/authorization.",
                "category": "api"
            })

        return result

    def close(self):
        """Close the HTTP client."""
        self.client.close()
