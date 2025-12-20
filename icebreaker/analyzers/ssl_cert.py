"""
SSL/TLS certificate analyzer with expiration tracking.
"""
from __future__ import annotations
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, List
import OpenSSL.crypto
from icebreaker.core.models import RunContext, Service, Finding


class SSLCertAnalyzer:
    """Icebreaker analyzer for SSL/TLS certificates."""

    id = "ssl_cert"
    consumes = ["service:https", "service:ssl", "service:tls"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        """
        Analyze SSL/TLS certificate for a service.

        Args:
            ctx: Run context
            service: Service to analyze

        Returns:
            List of findings
        """
        findings = []
        analyzer = SSLCertificateAnalyzer()

        try:
            result = analyzer.analyze(service.target, service.port)

            for finding_dict in result.get("findings", []):
                # Add description and impact based on finding type
                description = finding_dict.get("description", "")
                impact = ""
                references = []

                title = finding_dict["title"]
                if "Expired SSL Certificate" in title:
                    impact = "An expired SSL certificate will cause browsers to display security warnings, preventing users from accessing the site. This can lead to loss of trust, revenue, and potential data exposure if users bypass the warnings."
                    references = ["CWE-295", "CWE-298"]
                elif "Expiring Soon" in title:
                    impact = "If the certificate expires without renewal, browsers will display security warnings and block access to the site, causing service disruption and potential data exposure."
                    references = ["CWE-295"]
                elif "Expiring" in title:
                    impact = "Certificate expiration will cause browsers to display security warnings, potentially disrupting service and user access."
                    references = ["CWE-295"]
                elif "Self-Signed" in title:
                    impact = "Self-signed certificates are not trusted by browsers by default, causing security warnings for all users. This can lead to users bypassing security warnings, creating vulnerability to man-in-the-middle attacks."
                    references = ["CWE-295", "CWE-296"]
                elif "Weak Certificate Signature Algorithm" in title:
                    impact = "Weak signature algorithms like SHA-1 can be exploited to forge certificates, allowing attackers to impersonate the server and intercept encrypted traffic."
                    references = ["CWE-327", "CVE-2017-15361"]
                elif "Weak SSL Key Size" in title:
                    impact = "Small key sizes can be broken with sufficient computing power, allowing attackers to decrypt traffic or forge certificates. Modern standards require at least 2048-bit RSA keys."
                    references = ["CWE-326", "NIST-SP-800-57"]

                import uuid
                # Generate unique ID with UUID to prevent duplicates
                unique_id = f"ssl_cert.{finding_dict.get('category', 'misc')}.{service.target}.{service.port}.{uuid.uuid4().hex[:8]}"
                findings.append(Finding(
                    id=unique_id,
                    title=finding_dict["title"],
                    severity=finding_dict["severity"].upper(),
                    target=service.target,
                    port=service.port,
                    tags=["ssl", "tls", finding_dict.get("category", "cert")],
                    details=result,
                    description=description,
                    impact=impact,
                    recommendation=finding_dict.get("recommendation"),
                    references=references
                ))

        except Exception as e:
            # Silently skip if SSL analysis fails
            pass

        return findings


class SSLCertificateAnalyzer:
    """Analyzer for SSL/TLS certificates."""

    def __init__(self):
        self.timeout = 5

    def analyze(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate for a target.

        Args:
            target: Target hostname or IP
            port: Target port (default 443)

        Returns:
            Dictionary with certificate information and findings
        """
        findings = []
        cert_info = {
            "target": target,
            "port": port,
            "has_ssl": False,
            "findings": findings
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1, cert_bin
                    )

                    cert_info["has_ssl"] = True
                    cert_info["protocol"] = ssock.version()
                    cert_info["cipher"] = ssock.cipher()

                    # Parse certificate
                    self._parse_certificate(cert, cert_info, findings)

        except Exception as e:
            cert_info["error"] = str(e)

        return cert_info

    def _parse_certificate(
        self,
        cert: OpenSSL.crypto.X509,
        cert_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ):
        """Parse certificate and check for issues."""

        # Subject information
        subject = cert.get_subject()
        cert_info["subject"] = {
            "common_name": subject.CN if hasattr(subject, "CN") else None,
            "organization": subject.O if hasattr(subject, "O") else None,
            "country": subject.C if hasattr(subject, "C") else None,
        }

        # Issuer information
        issuer = cert.get_issuer()
        cert_info["issuer"] = {
            "common_name": issuer.CN if hasattr(issuer, "CN") else None,
            "organization": issuer.O if hasattr(issuer, "O") else None,
        }

        # Validity period
        not_before = datetime.strptime(
            cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
        )
        not_after = datetime.strptime(
            cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
        )

        cert_info["valid_from"] = not_before.isoformat()
        cert_info["valid_until"] = not_after.isoformat()

        # Check expiration
        days_until_expiry = (not_after - datetime.now()).days
        cert_info["days_until_expiry"] = days_until_expiry

        if days_until_expiry < 0:
            findings.append({
                "title": "Expired SSL Certificate",
                "severity": "critical",
                "description": f"SSL certificate expired {abs(days_until_expiry)} days ago.",
                "recommendation": "Renew the SSL certificate immediately.",
                "category": "ssl"
            })
        elif days_until_expiry < 30:
            findings.append({
                "title": "SSL Certificate Expiring Soon",
                "severity": "high",
                "description": f"SSL certificate will expire in {days_until_expiry} days.",
                "recommendation": "Renew the SSL certificate as soon as possible.",
                "category": "ssl"
            })
        elif days_until_expiry < 60:
            findings.append({
                "title": "SSL Certificate Expiring",
                "severity": "medium",
                "description": f"SSL certificate will expire in {days_until_expiry} days.",
                "recommendation": "Plan to renew the SSL certificate soon.",
                "category": "ssl"
            })

        # Check if self-signed
        if cert.get_issuer() == cert.get_subject():
            cert_info["self_signed"] = True
            findings.append({
                "title": "Self-Signed SSL Certificate",
                "severity": "medium",
                "description": "The SSL certificate is self-signed, which will cause browser warnings.",
                "recommendation": "Use a certificate from a trusted Certificate Authority.",
                "category": "ssl"
            })
        else:
            cert_info["self_signed"] = False

        # Check signature algorithm
        sig_alg = cert.get_signature_algorithm().decode('ascii')
        cert_info["signature_algorithm"] = sig_alg

        if 'sha1' in sig_alg.lower():
            findings.append({
                "title": "Weak Certificate Signature Algorithm",
                "severity": "medium",
                "description": f"Certificate uses weak signature algorithm: {sig_alg}",
                "recommendation": "Use SHA-256 or stronger signature algorithm.",
                "category": "ssl"
            })

        # Check key size
        pubkey = cert.get_pubkey()
        key_size = pubkey.bits()
        cert_info["key_size"] = key_size

        if key_size < 2048:
            findings.append({
                "title": "Weak SSL Key Size",
                "severity": "high",
                "description": f"Certificate uses weak key size: {key_size} bits",
                "recommendation": "Use at least 2048-bit RSA keys or 256-bit ECDSA keys.",
                "category": "ssl"
            })

        # Check for Subject Alternative Names (SAN)
        try:
            san_extension = None
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    san_extension = str(ext)
                    break

            if san_extension:
                cert_info["san"] = san_extension
        except Exception:
            pass

        # Serial number
        cert_info["serial_number"] = cert.get_serial_number()

        # Version
        cert_info["version"] = cert.get_version() + 1
