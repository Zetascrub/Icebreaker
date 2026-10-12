from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional

from icebreaker.core.models import RunContext, Service, Finding

# Ports that commonly serve HTTPS even when the service name wasn't resolved to "https"
_COMMON_HTTPS_PORTS = {443, 8443, 8834, 9443, 4443, 7443, 10443}


class TLSAnalyzer:
    """
    Analyzer for SSL/TLS vulnerabilities.

    Checks for:
    - Untrusted / self-signed certificate chain
    - Expired / expiring certificates
    - Hostname / CN mismatch
    - Weak protocol versions (SSLv3, TLS 1.0, TLS 1.1)
    - Certificate information (INFO)

    Runs on service:https AND on any port in _COMMON_HTTPS_PORTS.
    """

    id = "tls_analyzer"

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        is_https_service = (service.name or "").lower() in ("https", "ssl")
        is_https_port = service.port in _COMMON_HTTPS_PORTS
        if not (is_https_service or is_https_port):
            return []
        return await self._analyse_tls(service)

    async def _analyse_tls(self, service: Service) -> List[Finding]:
        """Full TLS analysis for a service known or suspected to serve HTTPS."""
        findings: List[Finding] = []

        # ------------------------------------------------------------------
        # Pass 1: verified connection — detect trust chain failures
        # ------------------------------------------------------------------
        trust_error: Optional[str] = None
        try:
            verified_ctx = ssl.create_default_context()
            verified_ctx.check_hostname = False   # we check it manually below
            # verify_mode stays CERT_REQUIRED (default)
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    service.target, service.port,
                    ssl=verified_ctx,
                    server_hostname=service.target,
                ),
                timeout=5.0,
            )
            w.close()
            await w.wait_closed()
        except ssl.SSLCertVerificationError as e:
            trust_error = str(e)
        except asyncio.TimeoutError:
            return findings   # port not reachable — skip silently
        except (ConnectionRefusedError, OSError):
            return findings   # not a TLS service on this port
        except Exception:
            pass              # other SSL errors handled below

        # ------------------------------------------------------------------
        # Pass 2: unverified connection — get cert details + protocol
        # ------------------------------------------------------------------
        try:
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    service.target, service.port,
                    ssl=unverified_ctx,
                    server_hostname=service.target,
                ),
                timeout=5.0,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                # CERT_NONE prevents Python from parsing the cert; use binary form
                # and parse with pyOpenSSL which is already a project dependency.
                cert_der = ssl_obj.getpeercert(binary_form=True)
                cert = _parse_der_cert(cert_der) if cert_der else {}
                protocol = ssl_obj.version() or ""
                cipher   = ssl_obj.cipher()

                # -- Protocol version checks --------------------------------
                if protocol in ("SSLv2", "SSLv3"):
                    findings.append(Finding(
                        id=f"tls.insecure_protocol.{service.target}.{service.port}",
                        title=f"Insecure SSL/TLS protocol: {protocol}",
                        severity="HIGH",
                        target=service.target, port=service.port,
                        tags=["tls", "protocol", "ssl"],
                        details={"protocol": protocol},
                        description=f"The server supports the insecure {protocol} protocol.",
                        impact="Known vulnerabilities including DROWN and POODLE allow decryption of traffic.",
                        recommendation="Disable this protocol; accept only TLS 1.2+.",
                        references=["CVE-2016-0800", "CVE-2014-3566", "CWE-327"],
                    ))
                elif protocol in ("TLSv1", "TLSv1.1"):
                    findings.append(Finding(
                        id=f"tls.deprecated_protocol.{service.target}.{service.port}",
                        title=f"Deprecated TLS protocol: {protocol}",
                        severity="MEDIUM",
                        target=service.target, port=service.port,
                        tags=["tls", "protocol"],
                        details={"protocol": protocol},
                        description=f"The server negotiated {protocol}, which is deprecated (RFC 8996).",
                        recommendation="Configure the server to accept only TLS 1.2 and TLS 1.3.",
                        references=["RFC-8996", "CWE-327"],
                    ))

                if cert:
                    issuer  = cert.get("issuer", ())
                    subject = cert.get("subject", ())
                    not_after  = cert.get("notAfter", "")
                    not_before = cert.get("notBefore", "")

                    # -- Certificate information (INFO) ----------------------
                    subject_cn  = _get_cn(subject)
                    issuer_cn   = _get_cn(issuer)
                    san_list    = _get_sans(cert)
                    findings.append(Finding(
                        id=f"tls.cert_info.{service.target}.{service.port}",
                        title="SSL Certificate Information",
                        severity="INFO",
                        target=service.target, port=service.port,
                        tags=["tls", "certificate", "info"],
                        description=(
                            f"Subject: {subject_cn or str(subject)} | "
                            f"Issuer: {issuer_cn or str(issuer)} | "
                            f"Valid: {not_before} – {not_after}"
                            + (f" | SANs: {', '.join(san_list)}" if san_list else "")
                        ),
                        details={
                            "subject": subject_cn, "issuer": issuer_cn,
                            "not_before": not_before, "not_after": not_after,
                            "sans": san_list,
                            "protocol": protocol,
                            "cipher": cipher[0] if cipher else None,
                        },
                    ))

                    # -- Trust chain -----------------------------------------
                    if trust_error:
                        self_signed = issuer and subject and issuer == subject
                        findings.append(Finding(
                            id=f"tls.untrusted_cert.{service.target}.{service.port}",
                            title="SSL Certificate Cannot Be Trusted",
                            severity="MEDIUM",
                            target=service.target, port=service.port,
                            tags=["tls", "certificate", "untrusted"],
                            description=(
                                "The SSL certificate presented by this service cannot be "
                                "verified against a trusted Certificate Authority. "
                                f"Reason: {trust_error}"
                            ),
                            impact=(
                                "Clients will receive trust warnings and may reject the "
                                "connection. An attacker could substitute a different "
                                "certificate in a MITM scenario."
                            ),
                            recommendation=(
                                "Obtain a certificate from a trusted CA (e.g. Let's Encrypt). "
                                "Ensure the full certificate chain is served."
                            ),
                            references=["CWE-295", "CWE-296"],
                            details={"trust_error": trust_error},
                        ))
                        if self_signed:
                            findings.append(Finding(
                                id=f"tls.self_signed.{service.target}.{service.port}",
                                title="SSL Self-Signed Certificate",
                                severity="MEDIUM",
                                target=service.target, port=service.port,
                                tags=["tls", "certificate", "self-signed"],
                                description=(
                                    "The SSL/TLS certificate is self-signed (issuer == subject). "
                                    f"Subject: {subject_cn}"
                                ),
                                recommendation=(
                                    "Replace with a certificate from a trusted CA."
                                ),
                                references=["CWE-295", "CWE-296"],
                                details={"subject": subject_cn, "issuer": issuer_cn},
                            ))
                    else:
                        # Trusted — still check self-signed (shouldn't happen but be safe)
                        if issuer and subject and issuer == subject:
                            findings.append(Finding(
                                id=f"tls.self_signed.{service.target}.{service.port}",
                                title="Self-signed SSL certificate detected",
                                severity="MEDIUM",
                                target=service.target, port=service.port,
                                tags=["tls", "certificate", "self-signed"],
                                details={"issuer": str(issuer)},
                                description="The SSL/TLS certificate is self-signed.",
                                recommendation="Obtain a certificate from a trusted CA.",
                                references=["CWE-295"],
                            ))

                    # -- CN / hostname mismatch --------------------------------
                    if not _hostname_matches(service.target, subject_cn, san_list):
                        findings.append(Finding(
                            id=f"tls.cn_mismatch.{service.target}.{service.port}",
                            title="SSL Certificate 'commonName' Mismatch",
                            severity="MEDIUM",
                            target=service.target, port=service.port,
                            tags=["tls", "certificate", "cn-mismatch"],
                            description=(
                                f"The certificate CN '{subject_cn}' does not match the "
                                f"hostname '{service.target}'."
                                + (f" SANs: {', '.join(san_list)}" if san_list else "")
                            ),
                            recommendation=(
                                "Obtain a certificate whose CN or SANs match the hostname "
                                "clients use to connect."
                            ),
                            references=["CWE-297"],
                            details={"cn": subject_cn, "hostname": service.target, "sans": san_list},
                        ))

                    # -- Expiration checks -------------------------------------
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now    = datetime.now(timezone.utc)
                            if expiry < now:
                                findings.append(Finding(
                                    id=f"tls.expired_cert.{service.target}.{service.port}",
                                    title="SSL certificate has expired",
                                    severity="HIGH",
                                    target=service.target, port=service.port,
                                    tags=["tls", "certificate", "expired"],
                                    details={"expired_on": not_after},
                                    description=f"The SSL certificate expired on {not_after}.",
                                    recommendation="Renew the certificate immediately.",
                                    references=["CWE-295"],
                                ))
                            elif (expiry - now).days < 30:
                                findings.append(Finding(
                                    id=f"tls.expiring_cert.{service.target}.{service.port}",
                                    title="SSL certificate expiring soon",
                                    severity="LOW",
                                    target=service.target, port=service.port,
                                    tags=["tls", "certificate", "expiring"],
                                    details={"expires_on": not_after, "days_remaining": (expiry - now).days},
                                    description=f"The SSL certificate expires in {(expiry - now).days} days ({not_after}).",
                                    recommendation="Renew before expiration.",
                                    references=["CWE-295"],
                                ))
                        except Exception:
                            pass

            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            pass
        except ssl.SSLError as e:
            findings.append(Finding(
                id=f"tls.ssl_error.{service.target}.{service.port}",
                title="SSL/TLS connection error",
                severity="INFO",
                target=service.target, port=service.port,
                tags=["tls", "error"],
                details={"error": str(e)},
                description=f"An SSL/TLS error occurred: {e}",
                recommendation="Review server SSL/TLS configuration.",
            ))
        except (ConnectionRefusedError, OSError):
            pass   # Port not serving TLS
        except Exception:
            pass

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_cn(rdns) -> str:
    """Extract commonName from an SSL cert issuer/subject tuple-of-tuples."""
    if not rdns:
        return ""
    for rdn in rdns:
        for attr, val in rdn:
            if attr == "commonName":
                return val
    return ""


def _get_sans(cert: dict) -> List[str]:
    """Extract Subject Alternative Names from a parsed cert dict."""
    sans = []
    for name_type, name_val in cert.get("subjectAltName", ()):
        if name_type == "DNS":
            sans.append(name_val)
        elif name_type == "IP Address":
            sans.append(name_val)
    return sans


def _parse_der_cert(der: bytes) -> dict:
    """
    Parse a DER-encoded certificate using pyOpenSSL and return a dict that
    mimics Python's ssl.getpeercert() format.
    """
    try:
        from OpenSSL import crypto
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der)

        def _rdn(obj) -> tuple:
            return tuple(
                (k.decode() if isinstance(k, bytes) else k,
                 v.decode() if isinstance(v, bytes) else v)
                for k, v in obj.get_components()
            )

        # subject / issuer as tuple-of-rdns matching ssl.getpeercert() format
        subject_tuple = ((_rdn(x509.get_subject()),))
        issuer_tuple  = ((_rdn(x509.get_issuer()),))

        # notBefore / notAfter
        not_before = x509.get_notBefore().decode() if x509.get_notBefore() else ""
        not_after  = x509.get_notAfter().decode() if x509.get_notAfter() else ""
        # Convert ASN1 YYYYMMDDHHMMSSZ → ssl module format "%b %d %H:%M:%S %Y GMT"
        def _asn1_to_ssl_date(asn1: str) -> str:
            try:
                from datetime import datetime
                dt = datetime.strptime(asn1[:14], "%Y%m%d%H%M%S")
                return dt.strftime("%b %d %H:%M:%S %Y GMT")
            except Exception:
                return asn1

        # Subject Alternative Names
        sans = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                for part in str(ext).split(","):
                    part = part.strip()
                    if part.startswith("DNS:"):
                        sans.append(("DNS", part[4:]))
                    elif part.startswith("IP Address:"):
                        sans.append(("IP Address", part[11:]))

        return {
            "subject": subject_tuple,
            "issuer": issuer_tuple,
            "notBefore": _asn1_to_ssl_date(not_before),
            "notAfter": _asn1_to_ssl_date(not_after),
            "subjectAltName": tuple(sans),
        }
    except Exception:
        return {}


def _hostname_matches(hostname: str, cn: str, sans: List[str]) -> bool:
    """
    Return True if *hostname* matches the cert CN or any SAN.
    Handles wildcard prefixes (*.example.com).
    """
    def _match(pattern: str, host: str) -> bool:
        if not pattern:
            return False
        pattern = pattern.lower()
        host    = host.lower()
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]   # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)]:
                return True
        return False

    candidates = ([cn] if cn else []) + sans
    return any(_match(c, hostname) for c in candidates)
