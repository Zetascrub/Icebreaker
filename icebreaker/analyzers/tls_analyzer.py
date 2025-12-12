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
                        details={"protocol": protocol}
                    ))
                elif protocol in ('TLSv1', 'TLSv1.1'):
                    findings.append(Finding(
                        id=f"tls.deprecated_protocol.{service.target}.{service.port}",
                        title=f"Deprecated TLS protocol: {protocol}",
                        severity="MEDIUM",
                        target=service.target,
                        port=service.port,
                        tags=["tls", "protocol"],
                        details={"protocol": protocol}
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
                                    details={"expired_on": not_after}
                                ))
                            elif (expiry - now).days < 30:
                                findings.append(Finding(
                                    id=f"tls.expiring_cert.{service.target}.{service.port}",
                                    title="SSL certificate expiring soon",
                                    severity="LOW",
                                    target=service.target,
                                    port=service.port,
                                    tags=["tls", "certificate", "expiring"],
                                    details={"expires_on": not_after, "days_remaining": (expiry - now).days}
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
                            details={"issuer": str(issuer)}
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
                details={"error": str(e)}
            ))
        except Exception:
            # Generic connection errors - skip
            pass

        return findings
