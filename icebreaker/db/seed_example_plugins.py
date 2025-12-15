"""
Seed the database with example plugins.

Run with: python -m icebreaker.db.seed_example_plugins
"""
from pathlib import Path
from sqlalchemy.orm import Session
from icebreaker.db.database import SessionLocal
from icebreaker.db.models import Plugin, FindingTemplate


def seed_ssh_cipher_plugin(db: Session):
    """Seed SSH weak cipher detection plugin."""

    # Check if plugin already exists
    existing = db.query(Plugin).filter(Plugin.plugin_id == "PLUGIN-SSH-001").first()
    if existing:
        print("✓ Plugin PLUGIN-SSH-001 already exists")
        return

    # Read the plugin code
    plugin_file = Path(__file__).parent.parent.parent / "examples" / "plugins" / "ssh_weak_ciphers.py"

    if not plugin_file.exists():
        print(f"❌ Plugin file not found: {plugin_file}")
        return

    code = plugin_file.read_text()

    # Create plugin
    plugin = Plugin(
        plugin_id="PLUGIN-SSH-001",
        name="SSH Weak Cipher Detection",
        description="Detects SSH servers using weak or deprecated ciphers (CBC mode) and old SSH protocol versions",
        author="Icebreaker Security Team",
        version="1.0.0",
        target_services=["ssh"],
        target_ports=[22, 2222],  # Common SSH ports
        code_type="inline",
        code=code,
        enabled=True,
        severity="HIGH",
        tags=["ssh", "cipher", "crypto", "cbc", "weak-crypto"],
        timeout_seconds=30,
        required_variables=["target", "port", "service", "banner"]
    )

    db.add(plugin)
    db.commit()
    print(f"✅ Created plugin: {plugin.plugin_id} - {plugin.name}")


def seed_http_tls_plugin(db: Session):
    """Seed HTTP/HTTPS TLS version check plugin."""

    existing = db.query(Plugin).filter(Plugin.plugin_id == "PLUGIN-TLS-001").first()
    if existing:
        print("✓ Plugin PLUGIN-TLS-001 already exists")
        return

    code = '''
"""
Plugin: TLS Version Check for HTTPS Services
Checks if HTTPS services support deprecated TLS versions (TLS 1.0, TLS 1.1)
"""
import ssl
import socket


def check():
    """Check HTTPS service for deprecated TLS versions."""
    findings = []

    deprecated_protocols = {
        'TLSv1': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1
    }

    for protocol_name, protocol_version in deprecated_protocols.items():
        try:
            context = ssl.SSLContext(protocol_version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # If we get here, the deprecated protocol is supported
                    findings.append({
                        'title': f'Deprecated {protocol_name} Protocol Supported',
                        'description': f'The HTTPS server at {target}:{port} supports the deprecated {protocol_name} protocol. {protocol_name} has known vulnerabilities and should be disabled.',
                        'severity': 'HIGH',
                        'recommendation': f'Disable {protocol_name} support. Configure the server to only support TLS 1.2 and TLS 1.3.',
                        'confidence': 1.0,
                        'raw_output': f'Successfully connected using {protocol_name}',
                        'references': [
                            'https://datatracker.ietf.org/doc/html/rfc8996',
                            'https://nvd.nist.gov/vuln/detail/CVE-2011-3389'
                        ]
                    })
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
            # Protocol not supported or connection failed - this is good
            pass
        except Exception as e:
            # Unexpected error - skip
            pass

    return {'findings': findings}
'''

    plugin = Plugin(
        plugin_id="PLUGIN-TLS-001",
        name="Deprecated TLS Version Detection",
        description="Checks HTTPS services for deprecated TLS versions (TLS 1.0, TLS 1.1)",
        author="Icebreaker Security Team",
        version="1.0.0",
        target_services=["https", "ssl"],
        target_ports=[443, 8443],
        code_type="inline",
        code=code,
        enabled=True,
        severity="HIGH",
        tags=["tls", "ssl", "https", "deprecated", "crypto"],
        timeout_seconds=30,
        required_variables=["target", "port"]
    )

    db.add(plugin)
    db.commit()
    print(f"✅ Created plugin: {plugin.plugin_id} - {plugin.name}")


def main():
    """Seed all example plugins."""
    print("Seeding example plugins...")

    db = SessionLocal()
    try:
        seed_ssh_cipher_plugin(db)
        seed_http_tls_plugin(db)

        print("\n✅ Plugin seeding completed!")
        print("\nTo test plugins, run a scan and they will automatically execute on matching services.")

    except Exception as e:
        print(f"\n❌ Error seeding plugins: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
