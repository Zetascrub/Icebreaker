"""
WAF and CDN detection analyzer.
"""
from __future__ import annotations
import httpx
from typing import Dict, Any, List, Optional


class WAFCDNAnalyzer:
    """Analyzer for detecting WAF and CDN usage."""

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["akamai", "x-akamai", "ak-"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-cdn"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "ModSecurity": ["mod_security", "NOYB"],
        "F5 BIG-IP": ["bigip", "f5"],
        "Barracuda": ["barra"],
        "Fortinet FortiWeb": ["fortigate", "fortiweb"],
        "Citrix NetScaler": ["ns_af", "citrix", "netscaler"],
        "Radware": ["x-protected-by"],
        "SonicWall": ["sonicwall"],
        "DenyAll": ["sessioncookie", "denali"],
        "dotDefender": ["x-dotdefender"],
    }

    CDN_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare-nginx", "__cfduid"],
        "Fastly": ["fastly", "x-fastly"],
        "Akamai": ["akamai", "x-akamai"],
        "CloudFront": ["x-amz-cf-id", "cloudfront"],
        "MaxCDN": ["x-cdn"],
        "KeyCDN": ["keycdn"],
        "Incapsula": ["x-cdn", "incapsula"],
        "Sucuri": ["x-sucuri-cache"],
        "Stackpath": ["x-stackpath"],
        "BunnyCDN": ["bunnycdn"],
        "Netlify": ["x-nf-request-id"],
        "Vercel": ["x-vercel"],
    }

    def __init__(self):
        self.client = httpx.Client(timeout=10.0, follow_redirects=True)

    def analyze(self, target: str, port: int = 80, use_https: bool = False) -> Dict[str, Any]:
        """
        Detect WAF and CDN on a target.

        Args:
            target: Target hostname or IP
            port: Target port
            use_https: Whether to use HTTPS

        Returns:
            Dictionary with WAF/CDN detection results and findings
        """
        findings = []
        result = {
            "target": target,
            "port": port,
            "waf_detected": [],
            "cdn_detected": [],
            "findings": findings
        }

        protocol = "https" if use_https or port == 443 else "http"
        url = f"{protocol}://{target}:{port}/"

        try:
            # Normal request
            response = self.client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text

            # Detect WAF
            waf_found = self._detect_waf(headers, body)
            result["waf_detected"] = waf_found

            if waf_found:
                findings.append({
                    "title": "Web Application Firewall Detected",
                    "severity": "info",
                    "description": f"WAF detected: {', '.join(waf_found)}. "
                                   "This may indicate additional security measures are in place.",
                    "recommendation": "Verify that WAF rules are properly configured and up to date.",
                    "category": "waf"
                })

            # Detect CDN
            cdn_found = self._detect_cdn(headers, body)
            result["cdn_detected"] = cdn_found

            if cdn_found:
                findings.append({
                    "title": "Content Delivery Network Detected",
                    "severity": "info",
                    "description": f"CDN detected: {', '.join(cdn_found)}. "
                                   "CDN can improve performance and provide DDoS protection.",
                    "recommendation": "Ensure CDN configuration follows security best practices.",
                    "category": "cdn"
                })

            # Test for WAF bypass with malicious payload
            try:
                malicious_url = f"{url}?id=1' OR '1'='1"
                mal_response = self.client.get(malicious_url)

                if mal_response.status_code in [403, 406, 419, 429, 503]:
                    if not waf_found:
                        findings.append({
                            "title": "Potential WAF Detected (Block Response)",
                            "severity": "info",
                            "description": "A malicious request was blocked, indicating WAF presence.",
                            "recommendation": "Continue monitoring WAF effectiveness.",
                            "category": "waf"
                        })
                elif mal_response.status_code == 200:
                    findings.append({
                        "title": "No WAF Protection Against SQL Injection",
                        "severity": "high",
                        "description": "SQL injection test payload was not blocked by WAF.",
                        "recommendation": "Implement or configure WAF to block SQL injection attempts.",
                        "category": "waf"
                    })
            except Exception:
                pass

            # Check security headers
            result["security_headers"] = self._check_security_headers(headers, findings)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _detect_waf(self, headers: Dict[str, str], body: str) -> List[str]:
        """Detect WAF from headers and body."""
        detected = []

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                if any(sig_lower in key or sig_lower in value.lower()
                       for key, value in headers.items()):
                    if waf_name not in detected:
                        detected.append(waf_name)
                    break
                # Check body
                if sig_lower in body.lower():
                    if waf_name not in detected:
                        detected.append(waf_name)
                    break

        return detected

    def _detect_cdn(self, headers: Dict[str, str], body: str) -> List[str]:
        """Detect CDN from headers and body."""
        detected = []

        for cdn_name, signatures in self.CDN_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                # Check headers
                if any(sig_lower in key or sig_lower in value.lower()
                       for key, value in headers.items()):
                    if cdn_name not in detected:
                        detected.append(cdn_name)
                    break

        return detected

    def _check_security_headers(
        self,
        headers: Dict[str, str],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, bool]:
        """Check for important security headers."""
        security_headers = {
            "strict-transport-security": False,
            "content-security-policy": False,
            "x-frame-options": False,
            "x-content-type-options": False,
            "x-xss-protection": False,
            "referrer-policy": False,
            "permissions-policy": False,
        }

        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = True

        # Report missing headers
        missing = [h for h, present in security_headers.items() if not present]
        if missing:
            findings.append({
                "title": "Missing Security Headers",
                "severity": "medium",
                "description": f"The following security headers are missing: {', '.join(missing)}",
                "recommendation": "Implement missing security headers to improve security posture.",
                "category": "headers"
            })

        return security_headers

    def close(self):
        """Close the HTTP client."""
        self.client.close()
