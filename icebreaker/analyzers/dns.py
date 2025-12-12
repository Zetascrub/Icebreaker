"""
DNS reconnaissance analyzer.
"""
from __future__ import annotations
import socket
import dns.resolver
import dns.reversename
from typing import List, Dict, Any


class DNSAnalyzer:
    """Analyzer for DNS reconnaissance."""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Perform DNS reconnaissance on a target.

        Args:
            target: Target hostname or IP

        Returns:
            Dictionary with DNS information and findings
        """
        findings = []
        dns_info = {
            "target": target,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "ptr_records": [],
            "findings": findings
        }

        # Skip if target is an IP address
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            # Perform reverse DNS lookup
            try:
                addr = dns.reversename.from_address(target)
                answers = self.resolver.resolve(addr, "PTR")
                dns_info["ptr_records"] = [str(rdata) for rdata in answers]
            except Exception:
                pass
            return dns_info

        # A records
        try:
            answers = self.resolver.resolve(target, "A")
            dns_info["a_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # AAAA records (IPv6)
        try:
            answers = self.resolver.resolve(target, "AAAA")
            dns_info["aaaa_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = self.resolver.resolve(target, "MX")
            dns_info["mx_records"] = [
                {"priority": rdata.preference, "exchange": str(rdata.exchange)}
                for rdata in answers
            ]
        except Exception:
            pass

        # NS records
        try:
            answers = self.resolver.resolve(target, "NS")
            dns_info["ns_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # TXT records
        try:
            answers = self.resolver.resolve(target, "TXT")
            dns_info["txt_records"] = [str(rdata) for rdata in answers]

            # Check for SPF records
            spf_records = [txt for txt in dns_info["txt_records"] if "v=spf1" in str(txt)]
            if not spf_records:
                findings.append({
                    "title": "Missing SPF Record",
                    "severity": "low",
                    "description": "No SPF (Sender Policy Framework) record found. This may allow email spoofing.",
                    "recommendation": "Add an SPF record to your DNS to prevent email spoofing.",
                    "category": "dns"
                })

            # Check for DMARC records
            try:
                dmarc_answers = self.resolver.resolve(f"_dmarc.{target}", "TXT")
                has_dmarc = any("v=DMARC1" in str(rdata) for rdata in dmarc_answers)
                if not has_dmarc:
                    findings.append({
                        "title": "Missing DMARC Policy",
                        "severity": "low",
                        "description": "No DMARC policy found. DMARC helps protect against email spoofing.",
                        "recommendation": "Implement a DMARC policy to enhance email security.",
                        "category": "dns"
                    })
            except Exception:
                findings.append({
                    "title": "Missing DMARC Policy",
                    "severity": "low",
                    "description": "No DMARC policy found. DMARC helps protect against email spoofing.",
                    "recommendation": "Implement a DMARC policy to enhance email security.",
                    "category": "dns"
                })

        except Exception:
            pass

        # CNAME records
        try:
            answers = self.resolver.resolve(target, "CNAME")
            dns_info["cname_records"] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        # Check for DNS zone transfer vulnerability
        if dns_info["ns_records"]:
            for ns in dns_info["ns_records"]:
                if self._check_zone_transfer(target, str(ns).rstrip('.')):
                    findings.append({
                        "title": "DNS Zone Transfer Enabled",
                        "severity": "medium",
                        "description": f"DNS zone transfer is enabled on nameserver {ns}. This exposes all DNS records.",
                        "recommendation": "Disable zone transfers (AXFR) for external nameservers.",
                        "category": "dns"
                    })

        return dns_info

    def _check_zone_transfer(self, domain: str, nameserver: str) -> bool:
        """Check if zone transfer is possible."""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=3))
            return zone is not None
        except Exception:
            return False
