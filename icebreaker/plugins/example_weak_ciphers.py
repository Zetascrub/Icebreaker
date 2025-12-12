"""
Example plugin: Weak SSL/TLS cipher detection.

This plugin demonstrates how to create custom analyzers for Icebreaker.
"""
from __future__ import annotations
import ssl
import socket
from typing import List, Dict, Any
from icebreaker.core.plugin_system import AnalyzerPlugin


class WeakCipherPlugin(AnalyzerPlugin):
    """Plugin to detect weak SSL/TLS ciphers."""

    name = "weak_cipher_detector"
    description = "Detects weak or deprecated SSL/TLS cipher suites"
    version = "1.0.0"
    author = "Icebreaker Team"

    # List of weak/insecure ciphers
    WEAK_CIPHERS = [
        "DES", "3DES", "RC4", "MD5", "NULL", "EXPORT",
        "anon", "ADH", "AECDH"
    ]

    def supports_service(self, service: str) -> bool:
        """This plugin only analyzes HTTPS/SSL services."""
        return service.lower() in ["https", "ssl", "tls"]

    async def analyze(
        self,
        target: str,
        port: int,
        service: str,
        banner: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Analyze SSL/TLS configuration for weak ciphers.

        Args:
            target: Target IP or hostname
            port: Target port
            service: Service name
            banner: Service banner (unused)

        Returns:
            List of findings
        """
        findings = []

        try:
            # Get supported ciphers
            supported_ciphers = self._get_supported_ciphers(target, port)

            if not supported_ciphers:
                return findings

            # Check for weak ciphers
            weak_ciphers_found = []
            for cipher in supported_ciphers:
                cipher_name = cipher.get("name", "")
                if any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS):
                    weak_ciphers_found.append(cipher_name)

            if weak_ciphers_found:
                findings.append({
                    "title": "Weak SSL/TLS Ciphers Detected",
                    "severity": "high",
                    "description": f"The server supports {len(weak_ciphers_found)} weak or "
                                   f"deprecated cipher suites: {', '.join(weak_ciphers_found[:5])}",
                    "recommendation": "Disable weak cipher suites and use only strong, "
                                      "modern ciphers (AES-GCM, ChaCha20-Poly1305).",
                    "references": [
                        "https://wiki.mozilla.org/Security/Server_Side_TLS",
                        "https://ssl-config.mozilla.org/"
                    ],
                    "cvss_score": 7.5,
                    "category": "ssl"
                })

            # Check for SSLv2/SSLv3 support
            if self._check_deprecated_protocols(target, port):
                findings.append({
                    "title": "Deprecated SSL/TLS Protocol Supported",
                    "severity": "critical",
                    "description": "The server supports SSLv2 or SSLv3, which are insecure "
                                   "and should be disabled.",
                    "recommendation": "Disable SSLv2 and SSLv3. Use TLS 1.2 or higher.",
                    "references": [
                        "https://tools.ietf.org/html/rfc7568"
                    ],
                    "cvss_score": 9.0,
                    "cve_ids": ["CVE-2014-3566"],  # POODLE
                    "category": "ssl"
                })

        except Exception as e:
            # Silently fail - this is just an example plugin
            pass

        return findings

    def _get_supported_ciphers(self, target: str, port: int) -> List[Dict[str, Any]]:
        """Get list of supported cipher suites."""
        supported = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        supported.append({
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        })
        except Exception:
            pass

        return supported

    def _check_deprecated_protocols(self, target: str, port: int) -> bool:
        """Check if server supports deprecated SSL protocols."""
        deprecated_protocols = [
            ssl.PROTOCOL_SSLv23,  # Will try SSLv2/v3 if available
        ]

        for protocol in deprecated_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((target, port), timeout=3) as sock:
                    with context.wrap_socket(sock) as ssock:
                        # If we can connect with deprecated protocol, it's supported
                        return True
            except Exception:
                continue

        return False
