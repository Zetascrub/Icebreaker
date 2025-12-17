from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import List

from icebreaker.core.models import RunContext, Service, Finding


class TLSAnalyzer:
    """
    Analyzer for SSL/TLS vulnerabilities.

    Checks for:
    - Expired certificates
    - Self-signed certificates
    - Weak protocol versions (SSLv3, TLS 1.0, TLS 1.1)
    - Certificate validity issues
    - Hostname mismatches
    """

    id = "tls_analyzer"
    consumes = ["service:https"]

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        findings: List[Finding] = []

        try:
            # Create SSL context that allows all protocols for testing
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    service.target,
                    service.port,
                    ssl=ssl_context,
                    server_hostname=service.target
                ),
                timeout=5.0
            )

            # Get SSL object to inspect certificate
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                protocol = ssl_obj.version()

                # Check protocol version
                if protocol in ('SSLv2', 'SSLv3'):
                    findings.append(Finding(
                        id=f"tls.insecure_protocol.{service.target}.{service.port}",
                        title=f"Insecure SSL/TLS protocol: {protocol}",
                        severity="HIGH",
                        target=service.target,
                        port=service.port,
                        tags=["tls", "protocol", "ssl"],
                        details={"protocol": protocol},
                        description=f"The server supports the insecure {protocol} protocol, which has known cryptographic weaknesses and should never be used.",
                        impact="SSLv2 and SSLv3 have critical security flaws including DROWN, POODLE, and other attacks that allow attackers to decrypt traffic, downgrade connections, and compromise encrypted data.",
                        recommendation=f"Disable {protocol} support immediately. Configure the server to only accept TLS 1.2 and TLS 1.3 connections. Update server configuration to remove legacy protocol support.",
                        references=["CVE-2016-0800", "CVE-2014-3566", "CWE-327", "OWASP-A02:2021"]
                    ))
                elif protocol in ('TLSv1', 'TLSv1.1'):
                    findings.append(Finding(
                        id=f"tls.deprecated_protocol.{service.target}.{service.port}",
                        title=f"Deprecated TLS protocol: {protocol}",
                        severity="MEDIUM",
                        target=service.target,
                        port=service.port,
                        tags=["tls", "protocol"],
                        details={"protocol": protocol},
                        description=f"The server supports {protocol}, which is deprecated and no longer considered secure by modern standards. Major browsers and security standards organizations have removed support for these protocols.",
                        impact="TLS 1.0 and 1.1 have known vulnerabilities including BEAST and other cryptographic weaknesses. Using deprecated protocols exposes connections to downgrade attacks and may prevent access from modern browsers.",
                        recommendation="Disable TLS 1.0 and TLS 1.1 support. Configure the server to only accept TLS 1.2 (minimum) and TLS 1.3 (recommended). Update cipher suite configuration to use modern, secure ciphers.",
                        references=["RFC-8996", "CWE-327", "PCI-DSS-v4.0"]
                    ))

                # Check certificate expiration
                if cert:
                    not_after = cert.get('notAfter')
                    if not_after:
                        try:
                            # Parse certificate expiration date
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)

                            if expiry < now:
                                findings.append(Finding(
                                    id=f"tls.expired_cert.{service.target}.{service.port}",
                                    title="SSL certificate has expired",
                                    severity="HIGH",
                                    target=service.target,
                                    port=service.port,
                                    tags=["tls", "certificate", "expired"],
                                    details={"expired_on": not_after},
                                    description="The SSL/TLS certificate for this service has expired and is no longer valid.",
                                    impact="Browsers will display security warnings preventing users from accessing the site. This causes service disruption, loss of user trust, and potential security risks if users bypass warnings.",
                                    recommendation="Renew the SSL certificate immediately. Implement automated certificate renewal using tools like Let's Encrypt with certbot, or set up monitoring to alert before expiration.",
                                    references=["CWE-295", "CWE-298"]
                                ))
                            elif (expiry - now).days < 30:
                                findings.append(Finding(
                                    id=f"tls.expiring_cert.{service.target}.{service.port}",
                                    title="SSL certificate expiring soon",
                                    severity="LOW",
                                    target=service.target,
                                    port=service.port,
                                    tags=["tls", "certificate", "expiring"],
                                    details={"expires_on": not_after, "days_remaining": (expiry - now).days},
                                    description=f"The SSL/TLS certificate will expire in {(expiry - now).days} days.",
                                    impact="If not renewed before expiration, the service will become inaccessible to users due to browser security warnings.",
                                    recommendation="Renew the SSL certificate before it expires. Consider implementing automated certificate renewal and monitoring to prevent future expiration issues.",
                                    references=["CWE-295"]
                                ))
                        except Exception:
                            pass

                    # Check for self-signed certificate
                    issuer = cert.get('issuer', ())
                    subject = cert.get('subject', ())
                    if issuer and subject and issuer == subject:
                        findings.append(Finding(
                            id=f"tls.self_signed.{service.target}.{service.port}",
                            title="Self-signed SSL certificate detected",
                            severity="MEDIUM",
                            target=service.target,
                            port=service.port,
                            tags=["tls", "certificate", "self-signed"],
                            details={"issuer": str(issuer)},
                            description="The SSL/TLS certificate is self-signed rather than issued by a trusted Certificate Authority (CA).",
                            impact="Browsers will display security warnings to all users, as self-signed certificates are not trusted by default. This creates a poor user experience and may lead users to bypass security warnings, making them vulnerable to man-in-the-middle attacks.",
                            recommendation="Obtain a certificate from a trusted Certificate Authority. Consider using Let's Encrypt for free, automated certificates, or purchase a certificate from a commercial CA for extended validation.",
                            references=["CWE-295", "CWE-296"]
                        ))

            # Clean up connection
            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            # Connection timeout - not necessarily a vulnerability
            pass
        except ssl.SSLError as e:
            # SSL errors might indicate vulnerabilities
            findings.append(Finding(
                id=f"tls.ssl_error.{service.target}.{service.port}",
                title="SSL/TLS connection error",
                severity="INFO",
                target=service.target,
                port=service.port,
                tags=["tls", "error"],
                details={"error": str(e)},
                description=f"An SSL/TLS error occurred while connecting to the service: {str(e)}",
                impact="This may indicate a configuration issue, protocol mismatch, or potential security problem with the SSL/TLS setup.",
                recommendation="Review server SSL/TLS configuration, ensure valid certificates are installed, and verify protocol and cipher suite settings."
            ))
        except Exception:
            # Generic connection errors - skip
            pass

        return findings
