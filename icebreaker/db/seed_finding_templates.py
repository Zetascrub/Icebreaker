"""
Seed database with finding templates.

This module contains standardized finding definitions with descriptions,
impact assessments, and remediation steps.
"""
from icebreaker.db.database import SessionLocal
from icebreaker.db.models import FindingTemplate


FINDING_TEMPLATES = [
    {
        "finding_id": "ICEBREAKER-001",
        "title": "Weak TLS Configuration Detected",
        "category": "TLS/SSL",
        "description": "The server supports deprecated TLS protocol versions (TLS 1.0 or TLS 1.1) which have known cryptographic weaknesses. These versions are no longer considered secure and have been deprecated by major standards bodies including IETF, PCI-DSS, and NIST.",
        "impact": "Attackers may be able to perform man-in-the-middle attacks, decrypt sensitive communications, or downgrade connections to use weak cipher suites. This could lead to exposure of sensitive data including credentials, personal information, and business data.",
        "remediation": "1. Disable TLS 1.0 and TLS 1.1 on all servers\n2. Enable only TLS 1.2 and TLS 1.3\n3. Configure strong cipher suites (ECDHE with AES-GCM)\n4. Test configuration with SSL Labs or similar tools\n5. Monitor for clients that may still require legacy protocols",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-326",
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "pci_dss": "Requirement 4.1",
        "references": [
            "https://www.rfc-editor.org/rfc/rfc8996.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        ]
    },
    {
        "finding_id": "ICEBREAKER-002",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "category": "HTTP Headers",
        "description": "The server does not set the HTTP Strict-Transport-Security header, which instructs browsers to only connect over HTTPS. Without HSTS, users may be vulnerable to protocol downgrade attacks and cookie hijacking.",
        "impact": "Users accessing the site over HTTP (even accidentally) won't be redirected to HTTPS by the browser. Attackers on the network can intercept initial HTTP requests, steal session cookies, or perform SSL stripping attacks. This is particularly dangerous on public WiFi networks.",
        "remediation": "1. Add the Strict-Transport-Security header to all HTTPS responses\n2. Set max-age to at least 31536000 (1 year)\n3. Include 'includeSubDomains' directive if all subdomains support HTTPS\n4. Consider adding 'preload' and submitting to HSTS preload list\n5. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-523",
        "owasp_2021": "A05:2021 – Security Misconfiguration",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ]
    },
    {
        "finding_id": "ICEBREAKER-003",
        "title": "Missing X-Frame-Options Header",
        "category": "HTTP Headers",
        "description": "The server does not set the X-Frame-Options or Content-Security-Policy frame-ancestors directive. This allows the page to be embedded in frames on other domains, potentially enabling clickjacking attacks.",
        "impact": "Attackers can embed the application in an invisible iframe on a malicious website. Users who interact with the malicious page may unknowingly perform actions in the vulnerable application, such as changing settings, making purchases, or transferring funds.",
        "remediation": "1. Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'\n2. Alternatively, use Content-Security-Policy: frame-ancestors 'self'\n3. For applications that need to be embedded, explicitly whitelist trusted domains\n4. Test with browser developer tools to verify frames are blocked\n5. Example: X-Frame-Options: SAMEORIGIN",
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-1021",
        "owasp_2021": "A05:2021 – Security Misconfiguration",
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        ]
    },
    {
        "finding_id": "ICEBREAKER-004",
        "title": "Missing X-Content-Type-Options Header",
        "category": "HTTP Headers",
        "description": "The server does not set the X-Content-Type-Options: nosniff header. This allows browsers to MIME-sniff content types, potentially causing files to be interpreted as a different type than intended, leading to XSS attacks.",
        "impact": "Attackers who can upload files or inject content may be able to exploit MIME confusion to execute malicious scripts. For example, a file uploaded as text/plain could be interpreted as text/html and execute JavaScript code.",
        "remediation": "1. Add X-Content-Type-Options: nosniff header to all responses\n2. Ensure Content-Type headers are set correctly for all resources\n3. Validate file uploads and set proper content types\n4. Test with various browsers to ensure sniffing is prevented\n5. Apply header globally through web server configuration",
        "severity": "LOW",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-430",
        "owasp_2021": "A05:2021 – Security Misconfiguration",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
        ]
    },
    {
        "finding_id": "ICEBREAKER-005",
        "title": "Self-Signed SSL/TLS Certificate",
        "category": "TLS/SSL",
        "description": "The server is using a self-signed SSL/TLS certificate that is not trusted by standard certificate authorities. This indicates the certificate was generated locally rather than issued by a trusted CA.",
        "impact": "Users will see security warnings in their browsers, potentially training them to ignore security warnings. Man-in-the-middle attacks cannot be detected as the certificate is already untrusted. This erodes user trust and may indicate improper certificate management.",
        "remediation": "1. Obtain a certificate from a trusted Certificate Authority (CA)\n2. Use free services like Let's Encrypt for automated certificate issuance\n3. Implement automated certificate renewal\n4. For internal services, set up an internal CA and distribute root certificate\n5. Ensure proper certificate chain is configured\n6. Monitor certificate expiration dates",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-295",
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "references": [
            "https://letsencrypt.org/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        ]
    },
    {
        "finding_id": "ICEBREAKER-006",
        "title": "Expiring or Expired SSL/TLS Certificate",
        "category": "TLS/SSL",
        "description": "The server's SSL/TLS certificate is either expired or will expire soon (within 30 days). Expired certificates cause browsers to block access and display security warnings.",
        "impact": "Users will be unable to access the service once the certificate expires. Browsers will display prominent warnings that the connection is not secure. This can cause service downtime, loss of user trust, and potential data exposure if users bypass warnings.",
        "remediation": "1. Renew the SSL/TLS certificate immediately if expired\n2. Set up automated certificate renewal (e.g., certbot for Let's Encrypt)\n3. Implement monitoring to alert before certificates expire\n4. Use certificate management tools to track all certificates\n5. Set renewal reminders at 60, 30, and 7 days before expiration\n6. Test certificate renewal process in non-production environment",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-298",
        "owasp_2021": "A02:2021 – Cryptographic Failures",
        "pci_dss": "Requirement 4.1",
        "references": [
            "https://www.ssl.com/faqs/what-happens-when-ssl-certificate-expires/",
            "https://letsencrypt.org/docs/"
        ]
    },
    {
        "finding_id": "ICEBREAKER-007",
        "title": "Server Information Disclosure",
        "category": "Information Disclosure",
        "description": "The server discloses its version information in HTTP headers (Server or X-Powered-By). This information helps attackers identify known vulnerabilities specific to the server software version.",
        "impact": "Attackers can quickly identify if the server is running outdated software with known vulnerabilities. This reduces reconnaissance time and allows targeted attacks against specific version vulnerabilities. Combined with other information, it aids in attack automation.",
        "remediation": "1. Remove or customize Server header to not include version information\n2. Remove X-Powered-By header completely\n3. Configure web server to suppress version disclosure\n   - Apache: ServerTokens Prod, ServerSignature Off\n   - Nginx: server_tokens off;\n   - IIS: Remove via URL Rewrite or custom headers\n4. Implement defense in depth - don't rely solely on hiding versions\n5. Keep all software up to date regardless of disclosure",
        "severity": "LOW",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200",
        "owasp_2021": "A05:2021 – Security Misconfiguration",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
        ]
    },
    {
        "finding_id": "ICEBREAKER-008",
        "title": "Open Port Detected",
        "category": "Network Security",
        "description": "An open port was detected on the target system. Open ports indicate services that are listening for network connections and may be accessible to unauthorized parties if not properly secured.",
        "impact": "Each open port represents a potential attack surface. If the service running on the port has vulnerabilities, it could be exploited for unauthorized access, data theft, or system compromise. Unnecessary open ports increase the attack surface unnecessarily.",
        "remediation": "1. Identify the service running on the port\n2. Verify the service is necessary for business operations\n3. If unnecessary, disable the service and close the port\n4. If necessary, restrict access using:\n   - Firewall rules to allow only trusted IP addresses\n   - VPN or SSH tunnel for remote access\n   - Network segmentation to isolate service\n5. Ensure the service is patched and properly configured\n6. Enable logging and monitoring for the service\n7. Regularly audit open ports across the network",
        "severity": "INFO",
        "cvss_score": 0.0,
        "cwe_id": "CWE-16",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"
        ]
    },
    {
        "finding_id": "ICEBREAKER-009",
        "title": "Missing Content Security Policy (CSP)",
        "category": "HTTP Headers",
        "description": "The server does not implement a Content Security Policy header. CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks by specifying which content sources are trusted.",
        "impact": "Without CSP, the application is more vulnerable to XSS attacks. Attackers who find an injection point can execute malicious scripts with full access to the page, potentially stealing credentials, performing actions as the user, or spreading malware.",
        "remediation": "1. Implement Content-Security-Policy header with appropriate directives\n2. Start with a restrictive policy:\n   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'\n3. Use CSP reporting to identify violations without breaking functionality:\n   Content-Security-Policy-Report-Only header\n4. Gradually refine policy based on application needs\n5. Avoid using 'unsafe-inline' and 'unsafe-eval' if possible\n6. Use nonces or hashes for inline scripts if needed\n7. Test thoroughly across all application pages",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-693",
        "owasp_2021": "A03:2021 – Injection",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        ]
    },
    {
        "finding_id": "ICEBREAKER-010",
        "title": "WAF or CDN Detected",
        "category": "Information Disclosure",
        "description": "A Web Application Firewall (WAF) or Content Delivery Network (CDN) was detected protecting this application. While this is generally positive for security, it confirms the presence of additional security layers that attackers may attempt to bypass.",
        "impact": "Knowing which WAF/CDN is in use allows attackers to research known bypass techniques specific to that platform. However, the presence of a WAF is overall beneficial for security. This is an informational finding to document the security architecture.",
        "remediation": "1. Ensure WAF rules are up to date and properly configured\n2. Enable WAF logging and monitor for bypass attempts\n3. Don't rely solely on WAF - implement security at application layer too\n4. Regularly review WAF configuration for effectiveness\n5. Consider hiding WAF signatures by customizing error pages\n6. Implement rate limiting and IP reputation features\n7. Test WAF effectiveness with authorized penetration testing",
        "severity": "INFO",
        "cvss_score": 0.0,
        "cwe_id": "CWE-200",
        "references": [
            "https://owasp.org/www-community/controls/Web_Application_Firewall"
        ]
    }
]


def seed_finding_templates():
    """Seed the database with finding templates."""
    db = SessionLocal()

    try:
        existing_count = db.query(FindingTemplate).count()

        if existing_count > 0:
            print(f"ℹ️  Database already contains {existing_count} finding templates. Skipping seed.")
            return

        print(f"🌱 Seeding database with {len(FINDING_TEMPLATES)} finding templates...")

        for template_data in FINDING_TEMPLATES:
            template = FindingTemplate(**template_data)
            db.add(template)

        db.commit()
        print(f"✅ Successfully seeded {len(FINDING_TEMPLATES)} finding templates!")

    except Exception as e:
        print(f"❌ Error seeding finding templates: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_finding_templates()
