from __future__ import annotations

import httpx
from typing import List

from icebreaker.core.models import RunContext, Service, Finding


class InfoDisclosure:
    """
    Analyzer for information disclosure vulnerabilities.

    Checks for exposure of:
    - .git directory
    - .env files
    - Backup files
    - Configuration files
    - Source code
    - Directory listings
    """

    id = "info_disclosure"
    consumes = ["service:http", "service:https"]

    # Common sensitive paths to check
    SENSITIVE_PATHS = [
        ".git/config",
        ".git/HEAD",
        ".env",
        ".env.local",
        ".env.production",
        "backup.zip",
        "backup.tar.gz",
        "database.sql",
        "db.sql",
        "dump.sql",
        "config.php",
        "config.yml",
        "config.json",
        "settings.py",
        "web.config",
        ".htaccess",
        "composer.json",
        "package.json",
        "yarn.lock",
        "Gemfile",
        "requirements.txt",
        "phpinfo.php",
        "info.php",
        "test.php",
        "admin",
        "administrator",
        ".DS_Store",
        "Thumbs.db",
    ]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        findings: List[Finding] = []

        # Build base URL
        scheme = "https" if service.name == "https" else "http"
        base_url = f"{scheme}://{service.target}"
        if (scheme == "http" and service.port != 80) or (scheme == "https" and service.port != 443):
            base_url += f":{service.port}"

        # Check for sensitive file exposure
        async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=False) as client:
            for path in self.SENSITIVE_PATHS:
                try:
                    url = f"{base_url}/{path}"
                    resp = await client.head(url)

                    # Check if file exists (200, 403 means exists but forbidden)
                    if resp.status_code in (200, 403):
                        severity = "HIGH" if resp.status_code == 200 else "MEDIUM"
                        findings.append(Finding(
                            id=f"info_disclosure.{path.replace('.', '_').replace('/', '_')}.{service.target}.{service.port}",
                            title=f"Sensitive file exposed: {path}",
                            severity=severity,
                            target=service.target,
                            port=service.port,
                            tags=["http", "info-disclosure", "sensitive-files"],
                            details={
                                "path": path,
                                "url": url,
                                "status": resp.status_code
                            }
                        ))
                except Exception:
                    # Connection errors, timeouts - skip this path
                    continue

        # Check for directory listing on root
        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=False) as client:
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    # Simple heuristic for directory listing
                    if ("index of" in content or
                        "<title>directory listing" in content or
                        "parent directory" in content):
                        findings.append(Finding(
                            id=f"info_disclosure.directory_listing.{service.target}.{service.port}",
                            title="Directory listing enabled",
                            severity="MEDIUM",
                            target=service.target,
                            port=service.port,
                            tags=["http", "info-disclosure", "directory-listing"],
                            details={"url": base_url}
                        ))
        except Exception:
            pass

        return findings
