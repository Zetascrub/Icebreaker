"""
CVE and vulnerability database integration.
"""
from __future__ import annotations
import re
import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import json
import os


class CVEService:
    """Service for looking up CVE information from NVD."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_DIR = "/data/cve_cache" if os.path.exists("/data") else "./cve_cache"
    CACHE_DURATION = timedelta(days=7)

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize CVE service.

        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.client = httpx.Client(timeout=30.0)
        os.makedirs(self.CACHE_DIR, exist_ok=True)

    def _get_cache_path(self, cve_id: str) -> str:
        """Get cache file path for a CVE ID."""
        return os.path.join(self.CACHE_DIR, f"{cve_id}.json")

    def _is_cache_valid(self, cache_path: str) -> bool:
        """Check if cache file is still valid."""
        if not os.path.exists(cache_path):
            return False

        mtime = datetime.fromtimestamp(os.path.getmtime(cache_path))
        return datetime.now() - mtime < self.CACHE_DURATION

    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Look up CVE information.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            CVE information dict or None if not found
        """
        # Check cache first
        cache_path = self._get_cache_path(cve_id)
        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass

        # Query NVD API
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = self.client.get(
                self.NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            if data.get("vulnerabilities"):
                cve_data = self._parse_cve_data(data["vulnerabilities"][0])

                # Cache the result
                with open(cache_path, 'w') as f:
                    json.dump(cve_data, f)

                return cve_data
        except Exception as e:
            print(f"Error looking up CVE {cve_id}: {e}")

        return None

    def _parse_cve_data(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NVD API response into simplified format."""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        # Get description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS scores
        metrics = cve.get("metrics", {})
        cvss_v3 = None
        cvss_v2 = None

        if "cvssMetricV31" in metrics:
            cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]

        if "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]

        # Determine severity
        severity = "UNKNOWN"
        base_score = 0.0

        if cvss_v3:
            severity = cvss_v3.get("baseSeverity", "UNKNOWN")
            base_score = cvss_v3.get("baseScore", 0.0)
        elif cvss_v2:
            base_score = cvss_v2.get("baseScore", 0.0)
            if base_score >= 7.0:
                severity = "HIGH"
            elif base_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Get references
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", "")
            })

        # Check for known exploits
        has_exploit = any(
            "exploit" in ref.get("url", "").lower() or
            "exploit" in " ".join(ref.get("tags", [])).lower()
            for ref in cve.get("references", [])
        )

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "cvss_score": base_score,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "references": references,
            "has_known_exploit": has_exploit,
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", "")
        }

    def search_by_cpe(self, cpe: str) -> List[Dict[str, Any]]:
        """
        Search for CVEs by CPE (Common Platform Enumeration).

        Args:
            cpe: CPE string (e.g., cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*)

        Returns:
            List of CVE information dicts
        """
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = self.client.get(
                self.NVD_API_URL,
                params={"cpeName": cpe},
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            return [
                self._parse_cve_data(vuln)
                for vuln in data.get("vulnerabilities", [])
            ]
        except Exception as e:
            print(f"Error searching CVEs for CPE {cpe}: {e}")
            return []

    def extract_version_from_banner(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version information from service banner.

        Args:
            banner: Service banner string
            service: Service name (e.g., 'apache', 'nginx', 'openssh')

        Returns:
            Version string if found
        """
        patterns = {
            'apache': r'Apache[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'nginx': r'nginx[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'openssh': r'OpenSSH[_\s]+(\d+\.\d+(?:p\d+)?)',
            'mysql': r'MySQL[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'postgresql': r'PostgreSQL[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'redis': r'Redis[/\s]+(\d+\.\d+(?:\.\d+)?)',
            'mongodb': r'MongoDB[/\s]+(\d+\.\d+(?:\.\d+)?)',
        }

        pattern = patterns.get(service.lower())
        if pattern:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def match_service_to_cves(self, service: str, version: str, banner: str = "") -> List[Dict[str, Any]]:
        """
        Match a service and version to known CVEs.

        Args:
            service: Service name
            version: Service version
            banner: Optional full banner for additional context

        Returns:
            List of matching CVEs
        """
        # Try to extract more precise version from banner if available
        if banner:
            extracted = self.extract_version_from_banner(banner, service)
            if extracted:
                version = extracted

        # Build CPE-like search (simplified)
        # In production, you'd want a proper CPE mapping database
        vendor_mapping = {
            'apache': 'apache:http_server',
            'nginx': 'nginx:nginx',
            'openssh': 'openbsd:openssh',
            'mysql': 'mysql:mysql',
            'postgresql': 'postgresql:postgresql',
        }

        vendor_product = vendor_mapping.get(service.lower())
        if not vendor_product:
            return []

        cpe = f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"
        return self.search_by_cpe(cpe)

    def close(self):
        """Close the HTTP client."""
        self.client.close()
