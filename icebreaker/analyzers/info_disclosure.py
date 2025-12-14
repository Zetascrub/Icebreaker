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

    def _verify_file_content(self, path: str, content: str, content_length: int) -> bool:
        """
        Verify that file content looks legitimate based on the file type.

        Args:
            path: The file path being checked
            content: The response content as text
            content_length: Length of the content

        Returns:
            True if content looks legitimate, False otherwise
        """
        # If content is suspiciously short (< 10 bytes) for most file types
        if content_length < 10 and path not in ["admin", "administrator"]:
            return False

        content_lower = content.lower()

        # Verify .git files contain git-specific content
        if ".git/" in path:
            if "ref:" in content_lower or "[core]" in content_lower or "repository" in content_lower:
                return True
            return False

        # Verify .env files look like environment files
        if ".env" in path:
            # Should contain KEY=VALUE patterns or comments
            if "=" in content or "#" in content:
                return True
            return False

        # Verify config files contain configuration patterns
        if any(x in path for x in ["config.", "settings.", "web.config"]):
            # Should contain config-like patterns
            config_patterns = ["=", ":", "{", "[", "<"]
            if any(p in content for p in config_patterns):
                return True
            return False

        # Verify SQL files contain SQL syntax
        if ".sql" in path or "dump" in path:
            sql_keywords = ["select", "insert", "create", "drop", "table", "database", "--"]
            if any(keyword in content_lower for keyword in sql_keywords):
                return True
            return False

        # Verify JSON files are valid JSON
        if ".json" in path:
            if content.strip().startswith(("{", "[")):
                return True
            return False

        # Verify PHP files contain PHP code
        if ".php" in path:
            if "<?php" in content_lower or "<?=" in content_lower:
                return True
            return False

        # For other file types, if we got here with actual content, accept it
        return True

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
        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            for path in self.SENSITIVE_PATHS:
                try:
                    url = f"{base_url}/{path}"

                    # Use GET to verify the file actually exists and has content
                    resp = await client.get(url)

                    # Check if file exists and has actual content
                    if resp.status_code == 200:
                        content = resp.content
                        content_length = len(content)

                        # Verify the file has actual content (not just empty or error page)
                        if content_length == 0:
                            continue  # Empty response, likely not a real file

                        # Check for common error page indicators
                        text_lower = resp.text.lower()
                        error_indicators = [
                            "404 not found",
                            "file not found",
                            "page not found",
                            "not found on this server",
                            "error 404",
                            "no such file",
                            "does not exist"
                        ]

                        # Skip if it looks like an error page
                        if any(indicator in text_lower for indicator in error_indicators):
                            continue

                        # Verify content looks legitimate for specific file types
                        if not self._verify_file_content(path, resp.text, content_length):
                            continue

                        # This appears to be a real exposed file
                        severity = "HIGH"

                        # Store file preview (first 500 chars)
                        preview = resp.text[:500] if content_length > 500 else resp.text

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
                                "status": resp.status_code,
                                "content_length": content_length,
                                "content_type": resp.headers.get("content-type", ""),
                                "file_preview": preview
                            }
                        ))

                    elif resp.status_code == 403:
                        # File exists but is forbidden - still a finding
                        findings.append(Finding(
                            id=f"info_disclosure.{path.replace('.', '_').replace('/', '_')}.{service.target}.{service.port}",
                            title=f"Sensitive path exists (forbidden): {path}",
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
