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

    def _validate_file_content(self, path: str, content: str, content_type: str) -> bool:
        """
        Validate that the response actually contains the expected file content.

        Args:
            path: File path being checked
            content: Response content
            content_type: Content-Type header value

        Returns:
            True if content appears to be valid for this file type
        """
        content_lower = content.lower()

        # Git files
        if path.startswith(".git/"):
            return "[core]" in content or "ref:" in content or "repositoryformatversion" in content_lower

        # Environment files
        if ".env" in path:
            # Look for KEY=VALUE patterns common in .env files
            return "=" in content and not "<html" in content_lower

        # Backup archives
        if path.endswith((".zip", ".tar.gz", ".sql")):
            # Check content type or binary markers
            return ("application/zip" in content_type or
                    "application/x-gzip" in content_type or
                    "application/sql" in content_type or
                    "create table" in content_lower or
                    "insert into" in content_lower)

        # Config files (JSON, YAML, PHP, Python)
        if path.endswith(".json"):
            return (content.strip().startswith("{") or content.strip().startswith("[")) and not "<html" in content_lower

        if path.endswith((".yml", ".yaml")):
            return (":" in content and not "<html" in content_lower)

        if path.endswith(".php"):
            return "<?php" in content or "<?=" in content

        if path.endswith(".py"):
            return ("import " in content or "def " in content or "class " in content) and not "<html" in content_lower

        # Package manager files
        if path in ("composer.json", "package.json"):
            return ('"name"' in content or '"dependencies"' in content) and content.strip().startswith("{")

        if path in ("requirements.txt", "Gemfile"):
            # Should have package names, no HTML
            return not "<html" in content_lower and not "<center>200 ok</center>" in content_lower

        if path in ("yarn.lock",):
            return "# yarn lockfile" in content_lower or '"' in content

        # Generic check: if it looks like HTML but shouldn't be, reject it
        if path.endswith((".txt", ".lock", ".config", ".htaccess")):
            return not "<html" in content_lower and not "<center>200 ok</center>" in content_lower

        # For other files, accept if there's substantial content
        return True

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
                    resp = await client.get(url)

                    # Only report if we get a valid response with actual content
                    if resp.status_code == 200:
                        content = resp.text
                        content_length = len(content)

                        # Skip if response is too small (likely generic error page)
                        # Real files should be at least 100 bytes
                        if content_length < 100:
                            continue

                        # Validate content based on file type
                        is_valid = self._validate_file_content(path, content, resp.headers.get("content-type", ""))

                        if is_valid:
                            import uuid
                            unique_id = f"info_disclosure.{path.replace('.', '_').replace('/', '_')}.{service.target}.{service.port}.{uuid.uuid4().hex[:8]}"
                            findings.append(Finding(
                                id=unique_id,
                                title=f"Sensitive file exposed: {path}",
                                severity="HIGH",
                                target=service.target,
                                port=service.port,
                                tags=["http", "info-disclosure", "sensitive-files"],
                                details={
                                    "path": path,
                                    "url": url,
                                    "status": resp.status_code,
                                    "content_length": content_length,
                                    "content_type": resp.headers.get("content-type", ""),
                                    "preview": content[:500] if content else ""
                                }
                            ))
                    elif resp.status_code == 403:
                        # 403 means file exists but is forbidden
                        import uuid
                        unique_id = f"info_disclosure.{path.replace('.', '_').replace('/', '_')}.forbidden.{service.target}.{service.port}.{uuid.uuid4().hex[:8]}"
                        findings.append(Finding(
                            id=unique_id,
                            title=f"Sensitive file exists (forbidden): {path}",
                            severity="MEDIUM",
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
                        import uuid
                        unique_id = f"info_disclosure.directory_listing.{service.target}.{service.port}.{uuid.uuid4().hex[:8]}"
                        findings.append(Finding(
                            id=unique_id,
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
