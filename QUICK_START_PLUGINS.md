# Icebreaker Plugin System - Quick Start Guide

## What's Been Implemented ✅

### 1. Finding Import/Export with Unique IDs
- Export findings to CSV with all data
- Import findings from CSV with upsert logic (update existing, create new)
- Unique `finding_id` constraint in database
- UI buttons in scan detail page

### 2. Plugin-Based Vulnerability Detection (Nessus-style)
- Database model for storing plugins
- Plugin executor with variable injection
- Service/port-based filtering
- Automatic execution during scans
- Example plugins (SSH cipher check, TLS version check)

### 3. Plugin Management API
- List, create, update, delete plugins
- Enable/disable plugins
- View execution statistics

---

## Getting Started

### Step 1: Run Database Migration

Make `finding_id` unique in your database:

```bash
python -m icebreaker.db.migrate_unique_finding_id
```

Expected output:
```
Starting migration: Make finding_id unique...
✓ No duplicate finding_ids found
Adding unique constraint to finding_id...
✅ Migration completed successfully!
```

### Step 2: Seed Example Plugins

Load the example plugins into your database:

```bash
python -m icebreaker.db.seed_example_plugins
```

Expected output:
```
Seeding example plugins...
✅ Created plugin: PLUGIN-SSH-001 - SSH Weak Cipher Detection
✅ Created plugin: PLUGIN-TLS-001 - Deprecated TLS Version Detection

✅ Plugin seeding completed!
```

### Step 3: Restart Icebreaker

Restart the Docker container or the application:

```bash
docker-compose restart
# or
docker restart icebreaker-web
```

### Step 4: Run a Scan

1. Navigate to `/scans/new`
2. Add targets with SSH or HTTPS services (e.g., `192.168.1.1`, `example.com`)
3. Start the scan
4. Watch the logs - you should see plugin execution:

```
Scan 1: Executing plugins for 5 services
Scan 1: Plugins generated 2 findings
Scan 1: Plugin stats - Executed: 5, Success: 5, Failed: 0, Findings: 2
```

### Step 5: View Plugin Findings

1. Go to scan detail page
2. Check the **Findings** tab
3. Look for findings with titles like:
   - "SSH Server Supports Weak Ciphers"
   - "Deprecated TLS 1.0 Protocol Supported"

---

## Using the Import/Export Feature

### Export Findings

1. Go to any scan detail page
2. Click on the **Findings** tab
3. Click the **⬇ Export CSV** button
4. Save the CSV file

### Edit Findings in CSV

Open the CSV in Excel/LibreOffice and make changes:

```csv
Finding ID,Title,Severity,Status,Target,Port,...
FIND-ABC123,SQL Injection,HIGH,new,192.168.1.100,80,...
FIND-DEF456,XSS Vulnerability,MEDIUM,confirmed,192.168.1.100,443,...
```

You can:
- Change severity, status, or description
- Add new rows (leave Finding ID empty for new findings)
- Mark findings as false positives

### Import Modified Findings

1. Go back to the scan detail page
2. Click the **⬆ Import CSV** button
3. Select your modified CSV file
4. See the import summary:

```
Import complete: 2 created, 5 updated, 0 skipped
```

The page will automatically reload with updated findings!

---

## Managing Plugins

### View All Plugins (API)

```bash
curl http://localhost:9000/api/plugins
```

Response:
```json
[
  {
    "id": 1,
    "plugin_id": "PLUGIN-SSH-001",
    "name": "SSH Weak Cipher Detection",
    "enabled": true,
    "target_services": ["ssh"],
    "target_ports": [22, 2222],
    "execution_count": 15,
    "last_executed": "2025-12-15T10:30:00"
  },
  ...
]
```

### Enable/Disable a Plugin

```bash
curl -X POST http://localhost:9000/api/plugins/1/toggle
```

### View Plugin Details

```bash
curl http://localhost:9000/api/plugins/1
```

This shows the full plugin including the code.

---

## Creating Your Own Plugin

### Example: Check for Open Redis

Create a file `/data/plugins/redis_open.py`:

```python
"""
Plugin: Open Redis Detection
Checks if Redis is accessible without authentication
"""
import socket

def check():
    findings = []

    try:
        # Connect to Redis
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        # Send PING command
        sock.sendall(b"PING\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        sock.close()

        # Check if we got a PONG response without auth
        if "+PONG" in response:
            findings.append({
                'title': 'Unauthenticated Redis Access',
                'description': f'Redis server at {target}:{port} accepts commands without authentication',
                'severity': 'CRITICAL',
                'recommendation': 'Enable requirepass in redis.conf and restart Redis',
                'confidence': 1.0,
                'raw_output': response,
                'references': [
                    'https://redis.io/topics/security'
                ]
            })

    except Exception as e:
        # Connection failed or Redis requires auth (good)
        pass

    return {'findings': findings}
```

### Add Plugin to Database

```bash
curl -X POST http://localhost:9000/api/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_id": "PLUGIN-REDIS-001",
    "name": "Open Redis Detection",
    "description": "Checks for unauthenticated Redis access",
    "author": "Security Team",
    "version": "1.0.0",
    "target_services": ["redis"],
    "target_ports": [6379],
    "code_type": "file",
    "code_file_path": "/data/plugins/redis_open.py",
    "enabled": true,
    "severity": "CRITICAL",
    "tags": ["redis", "authentication", "misconfiguration"],
    "timeout_seconds": 30,
    "required_variables": ["target", "port"]
  }'
```

---

## Plugin Code Requirements

### Must Define check() Function

```python
def check():
    """Your security check code"""
    findings = []

    # Use injected variables:
    # - target (str): IP or hostname
    # - port (int): Port number
    # - service (str): Service name
    # - banner (str): Service banner
    # - scan_id (int): Current scan ID

    # Perform your check here...

    return {'findings': findings}
```

### Finding Format

```python
{
    'title': str,           # Required
    'description': str,     # Required
    'severity': str,        # Required: CRITICAL, HIGH, MEDIUM, LOW, INFO
    'recommendation': str,  # Required
    'confidence': float,    # Optional: 0.0-1.0
    'raw_output': str,      # Optional
    'references': list,     # Optional: URLs
    'cve_ids': list        # Optional: CVE identifiers
}
```

---

## Troubleshooting

### Plugins Not Executing

Check:
1. Plugin is enabled: `enabled = true`
2. Service matches: `target_services = ["ssh"]` and service discovered is "ssh"
3. Port matches (if specified): `target_ports = [22]`
4. Check logs for errors: `docker logs icebreaker-web`

### Import Fails

Common issues:
- CSV missing required columns: `Title`, `Severity`, `Target`
- Invalid severity values (must be: CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Malformed CSV (check for proper escaping of commas/quotes)
- Duplicate finding_id (should not happen after migration)

### Finding Not Created

- Plugin must return `{'findings': [...]}`
- Each finding must have required fields
- Check timeout - increase `timeout_seconds` if needed
- Review logs for Python errors in plugin code

---

## File Locations

```
icebreaker/
├── db/
│   ├── models.py                      # Plugin and Finding models
│   ├── migrate_unique_finding_id.py   # Migration script
│   └── seed_example_plugins.py        # Seed script
├── core/
│   └── plugin_executor.py             # Plugin execution engine
├── api/
│   └── routers/
│       ├── exports.py                 # Export/import endpoints
│       ├── plugins.py                 # Plugin management API
│       └── scans.py                   # Scan workflow (plugin integration)
├── web/
│   └── templates/
│       └── scan_detail.html           # Import/export UI
└── examples/
    └── plugins/
        └── ssh_weak_ciphers.py        # Example plugin

/data/plugins/                         # Your custom plugins go here
```

---

## Next Steps

1. ✅ Test the import/export workflow
2. ✅ Run a scan and verify plugins execute
3. ✅ Create your first custom plugin
4. ⏳ Build a plugin management UI (web interface)
5. ⏳ Add more example plugins for common services

---

## API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/exports/scans/{scan_id}/findings.csv` | Export findings to CSV |
| POST | `/api/imports/scans/{scan_id}/findings.csv` | Import findings from CSV |
| GET | `/api/plugins` | List all plugins |
| GET | `/api/plugins/{id}` | Get plugin details |
| POST | `/api/plugins` | Create new plugin |
| PUT | `/api/plugins/{id}` | Update plugin |
| DELETE | `/api/plugins/{id}` | Delete plugin |
| POST | `/api/plugins/{id}/toggle` | Enable/disable plugin |

---

## Success Indicators

After setup, you should see:

✅ Database migration completes without errors
✅ Example plugins seed successfully
✅ Scans show "Executing plugins for X services" in logs
✅ Plugin-generated findings appear in scan results
✅ Export CSV downloads with all finding data
✅ Import CSV updates existing findings and creates new ones
✅ API endpoints return plugin data

**Everything is working!** 🎉
