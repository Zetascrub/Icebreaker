"""
Add the Scan Info failsafe plugin to the database.

This plugin always triggers for every discovered service to provide
scan metadata and verify plugin execution is working.
"""
from icebreaker.db.database import SessionLocal
from icebreaker.db.models import Plugin
from datetime import datetime


def main():
    db = SessionLocal()

    # Scan Info Plugin - Always triggers as failsafe
    scan_info_plugin = Plugin(
        plugin_id='CORE-SCAN-INFO-001',
        name='Scan Information',
        description='Always-on plugin that creates an informational finding for each discovered service. Acts as a failsafe to verify plugin execution.',
        code_type='inline',
        code="""# Scan Information Plugin
# This plugin always triggers to provide scan metadata
# Acts as a failsafe to verify plugin execution is working

def check():
    # Variables available: target, port, service, banner
    from datetime import datetime

    findings = []

    # Create informational finding with scan details
    banner_info = banner[:100] if banner else 'No banner detected'

    findings.append({
        'title': f'Service Discovered: {service.upper()} on port {port}',
        'severity': 'INFO',
        'description': f'''Service discovery information:
- Target: {target}
- Port: {port}
- Service: {service}
- Banner: {banner_info}
- Discovery Time: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}

This is an informational finding that confirms the service was discovered and analyzed by the plugin system.''',
        'recommendation': 'No action required. This is informational only.'
    })

    return {'findings': findings}
""",
        enabled=True,
        severity='INFO',
        target_services=[],  # Empty = matches ALL services
        target_ports=[],     # Empty = matches ALL ports
        tags=['info', 'discovery', 'metadata'],
        timeout_seconds=5,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    # Check if already exists
    existing = db.query(Plugin).filter(Plugin.plugin_id == 'CORE-SCAN-INFO-001').first()
    if existing:
        print('Plugin already exists, updating...')
        existing.name = scan_info_plugin.name
        existing.description = scan_info_plugin.description
        existing.code = scan_info_plugin.code
        existing.enabled = scan_info_plugin.enabled
        existing.severity = scan_info_plugin.severity
        existing.target_services = scan_info_plugin.target_services
        existing.target_ports = scan_info_plugin.target_ports
        existing.tags = scan_info_plugin.tags
        existing.updated_at = datetime.utcnow()
    else:
        print('Creating new plugin...')
        db.add(scan_info_plugin)

    db.commit()
    print('✓ Scan Info plugin created/updated successfully')
    print(f'  Plugin ID: CORE-SCAN-INFO-001')
    print(f'  Matches: ALL services (failsafe)')
    print(f'  Enabled: True')

    db.close()


if __name__ == '__main__':
    main()
