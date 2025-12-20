"""
Seed database with analyzer plugins.

This script converts all built-in analyzers to plugins so they can be
managed, enabled/disabled, and customized through the plugin system.
"""
import sys
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from icebreaker.db.models import Base, Plugin


def seed_analyzer_plugins(db_path="data/icebreaker.db"):
    """Seed all built-in analyzers as plugins."""

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    analyzers = [
        {
            "plugin_id": "ANALYZER-HTTP-001",
            "name": "HTTP Basic Analyzer",
            "description": "Detects server headers, missing titles, and basic HTTP security issues",
            "author": "Icebreaker Team",
            "version": "1.0.0",
            "target_services": ["http", "https"],
            "target_ports": [],  # All HTTP/HTTPS ports
            "code_type": "inline",
            "code": """
# HTTP Basic Analyzer
# Variables available: target, port, service, banner
import httpx

async def check():
    findings = []

    try:
        # Use the 'service' variable to determine protocol
        # service will be "http" or "https" based on plugin Target Services config
        use_https = service.lower() == "https"
        base_url = f"{'https' if use_https else 'http'}://{target}:{port}"

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
            resp = await client.get(base_url)

            # Check for server header exposure
            if 'server' in resp.headers:
                findings.append({
                    'title': f"Server Header Exposed: {resp.headers['server']}",
                    'severity': 'LOW',
                    'description': f"Server header reveals: {resp.headers['server']}",
                    'recommendation': 'Configure the web server to hide or obfuscate the Server header'
                })

            # Check for missing page title
            if '<title>' not in resp.text.lower():
                findings.append({
                    'title': 'Missing HTML Title Tag',
                    'severity': 'INFO',
                    'description': 'Page does not have a <title> tag',
                    'recommendation': 'Add descriptive title tags to improve SEO and user experience'
                })
    except:
        pass

    return {'findings': findings}
""",
            "enabled": True,
            "severity": "LOW",
            "tags": ["http", "headers", "info-disclosure"],
            "timeout_seconds": 10
        },
        {
            "plugin_id": "ANALYZER-SECURITY-HEADERS-001",
            "name": "Security Headers Analyzer",
            "description": "Checks for missing security headers (CSP, X-Frame-Options, HSTS, etc.)",
            "author": "Icebreaker Team",
            "version": "1.0.0",
            "target_services": ["http", "https"],
            "target_ports": [],
            "code_type": "inline",
            "code": """
# Security Headers Analyzer
# Variables available: target, port, service, banner
import httpx

async def check():
    findings = []

    try:
        # Use the 'service' variable - will be "http" or "https" based on Target Services
        use_https = service.lower() == "https"
        base_url = f"{'https' if use_https else 'http'}://{target}:{port}"

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(base_url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # CSP
            if 'content-security-policy' not in headers:
                findings.append({
                    'title': 'Missing Content-Security-Policy Header',
                    'severity': 'MEDIUM',
                    'recommendation': 'Implement a Content-Security-Policy header to prevent XSS attacks'
                })

            # X-Frame-Options
            if 'x-frame-options' not in headers:
                findings.append({
                    'title': 'Missing X-Frame-Options Header',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
                })

            # HSTS (only check for HTTPS services)
            if use_https and 'strict-transport-security' not in headers:
                findings.append({
                    'title': 'Missing HSTS Header',
                    'severity': 'MEDIUM',
                    'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS'
                })
    except:
        pass

    return {'findings': findings}
""",
            "enabled": True,
            "severity": "MEDIUM",
            "tags": ["http", "security-headers", "xss", "clickjacking"],
            "timeout_seconds": 10
        },
        {
            "plugin_id": "ANALYZER-TLS-001",
            "name": "TLS/SSL Analyzer",
            "description": "Checks for weak TLS versions, expired certificates, and SSL/TLS vulnerabilities",
            "author": "Icebreaker Team",
            "version": "1.0.0",
            "target_services": ["https", "ssl", "tls"],
            "target_ports": [443, 8443],
            "code_type": "inline",
            "code": """
# TLS/SSL Analyzer
# Variables available: target, port, service, banner
import ssl
import socket

def check():
    findings = []

    try:
        # Use injected 'target' and 'port' variables
        # Plugin will only run if service matches "https", "ssl", or "tls"
        # or if port matches 443 or 8443 (from Target Services/Ports config)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

                # Check TLS version
                if version in ['TLSv1', 'TLSv1.0', 'TLSv1.1']:
                    findings.append({
                        'title': f'Deprecated TLS Version: {version}',
                        'severity': 'HIGH',
                        'description': f'Server supports deprecated {version} protocol',
                        'recommendation': 'Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3'
                    })
    except:
        pass

    return {'findings': findings}
""",
            "enabled": True,
            "severity": "HIGH",
            "tags": ["tls", "ssl", "crypto", "certificate"],
            "timeout_seconds": 10
        },
        {
            "plugin_id": "ANALYZER-INFO-DISCLOSURE-001",
            "name": "Information Disclosure Analyzer",
            "description": "Detects exposed sensitive files (.git, .env, backups, configs, etc.)",
            "author": "Icebreaker Team",
            "version": "1.0.0",
            "target_services": ["http", "https"],
            "target_ports": [],
            "code_type": "inline",
            "code": """
# Information Disclosure Analyzer
# Variables available: target, port, service, banner
import httpx

async def check():
    findings = []

    # Sensitive paths to check
    sensitive_paths = [
        '/.git/config',
        '/.env',
        '/config.php',
        '/wp-config.php',
        '/backup.sql',
        '/.htaccess'
    ]

    try:
        # Use the 'service' variable - will be "http" or "https" from Target Services
        use_https = service.lower() == "https"
        base_url = f"{'https' if use_https else 'http'}://{target}:{port}"

        async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=False) as client:
            for path in sensitive_paths:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        findings.append({
                            'title': f'Sensitive File Exposed: {path}',
                            'severity': 'HIGH',
                            'description': f'Sensitive file accessible at {path}',
                            'recommendation': 'Remove or restrict access to sensitive files and directories'
                        })
                except:
                    continue
    except:
        pass

    return {'findings': findings}
""",
            "enabled": True,
            "severity": "HIGH",
            "tags": ["http", "info-disclosure", "sensitive-files"],
            "timeout_seconds": 15
        },
        {
            "plugin_id": "ANALYZER-SSH-001",
            "name": "SSH Banner Analyzer",
            "description": "Extracts SSH version and detects outdated SSH servers",
            "author": "Icebreaker Team",
            "version": "1.0.0",
            "target_services": ["ssh"],
            "target_ports": [22, 2222],
            "code_type": "inline",
            "code": """
# SSH Banner Analyzer
# Variables available: target, port, service, banner
import socket

def check():
    findings = []

    try:
        # Use injected 'target' and 'port' variables
        # Plugin only runs if service="ssh" or port in [22, 2222] (from Target Services/Ports)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        ssh_banner = sock.recv(1024).decode().strip()
        sock.close()

        if ssh_banner:
            findings.append({
                'title': f'SSH Banner: {ssh_banner}',
                'severity': 'INFO',
                'description': f'SSH server banner: {ssh_banner}'
            })

            # Check for very old versions
            if 'OpenSSH_5' in ssh_banner or 'OpenSSH_4' in ssh_banner:
                findings.append({
                    'title': 'Outdated SSH Version Detected',
                    'severity': 'HIGH',
                    'description': f'SSH version {ssh_banner} is outdated and may have known vulnerabilities',
                    'recommendation': 'Upgrade to the latest stable version of OpenSSH'
                })
    except:
        pass

    return {'findings': findings}
""",
            "enabled": True,
            "severity": "INFO",
            "tags": ["ssh", "banner", "version-detection"],
            "timeout_seconds": 10
        }
    ]

    print("🔄 Seeding analyzer plugins...")

    created = 0
    updated = 0
    skipped = 0

    for analyzer_data in analyzers:
        # Check if plugin already exists
        existing = db.query(Plugin).filter(Plugin.plugin_id == analyzer_data['plugin_id']).first()

        if existing:
            # Update existing plugin
            for key, value in analyzer_data.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.utcnow()
            updated += 1
            print(f"  ✓ Updated: {analyzer_data['name']}")
        else:
            # Create new plugin
            plugin = Plugin(**analyzer_data)
            db.add(plugin)
            created += 1
            print(f"  ✓ Created: {analyzer_data['name']}")

    db.commit()
    db.close()

    print(f"\n✅ Analyzer plugin seeding complete!")
    print(f"   Created: {created}")
    print(f"   Updated: {updated}")
    print(f"   Total: {created + updated}")
    print(f"\n💡 All analyzers are now managed as plugins and can be enabled/disabled via the web UI or API.")


if __name__ == "__main__":
    import sys
    db_path = sys.argv[1] if len(sys.argv) > 1 else "data/icebreaker.db"
    seed_analyzer_plugins(db_path)
