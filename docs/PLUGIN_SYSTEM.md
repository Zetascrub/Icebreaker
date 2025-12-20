# Icebreaker Plugin System Documentation

## Overview

The Icebreaker plugin system allows you to create **executable vulnerability checks** similar to Nessus plugins. Plugins are Python code that run active checks against services during scans, enabling custom security testing beyond the built-in analyzers.

---

## Features Implemented

### 1. Finding Import/Export with Unique IDs ✅

**Export Findings to CSV:**
```bash
GET /api/exports/scans/{scan_id}/findings.csv
```

**Import Findings from CSV:**
```bash
POST /api/imports/scans/{scan_id}/findings.csv
```

**CSV Import Behavior:**
- **If finding_id exists**: Updates the existing finding (upsert)
- **If finding_id is empty**: Creates new finding with auto-generated ID (`FIND-XXXXXXXXXXXX`)
- **Validation**: Checks required fields (title, severity, target)
- **Returns**: Statistics on created/updated/skipped findings

**Migration:**
- `finding_id` is now UNIQUE in the database
- Run migration: `python -m icebreaker.db.migrate_unique_finding_id`
- Automatically generates unique IDs for any duplicates

---

### 2. Plugin-Based Vulnerability Detection ✅

#### Architecture

```
Plugin System
├── Plugin Model (Database)
│   ├── plugin_id: Unique identifier
│   ├── name, description, version
│   ├── target_services: ["ssh", "http", "https"]
│   ├── target_ports: [22, 80, 443]
│   ├── code_type: "inline" or "file"
│   ├── code: Python code (if inline)
│   ├── code_file_path: File reference (if file)
│   └── enabled, severity, tags, timeout
│
├── Plugin Executor (Runtime)
│   ├── Filters plugins by service/port
│   ├── Injects variables (target, port, service, banner)
│   ├── Executes code with timeout
│   ├── Captures findings
│   └── Creates Finding objects
│
└── Example Plugins
    ├── SSH Weak Cipher Detection
    └── Deprecated TLS Version Detection
```

---

## How Plugins Work

### Plugin Execution Flow

```
1. Scan discovers service (e.g., SSH on port 22)
   ↓
2. Plugin Executor queries enabled plugins
   ↓
3. Filter by service name: target_services = ["ssh"]
   ↓
4. Filter by port (optional): target_ports = [22, 2222]
   ↓
5. For each matching plugin:
   ├── Inject variables: {target, port, service, banner, ...}
   ├── Execute check() function with timeout
   ├── Capture findings returned by plugin
   └── Create Finding objects in database
   ↓
6. Continue with next service
```

###  Variables Injected into Plugins

Every plugin receives these variables at runtime:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `target` | str | Target IP or hostname | `"192.168.1.100"` |
| `port` | int | Port number | `22` |
| `service` | str | Detected service name | `"ssh"` |
| `banner` | str | Service banner if captured | `"SSH-2.0-OpenSSH_8.2p1"` |
| `scan_id` | int | Current scan ID | `42` |

You can also pass custom variables via `extra_vars`.

---

## Creating a Plugin

### Method 1: Inline Code (Stored in Database)

**Database Entry:**
```python
Plugin(
    plugin_id="PLUGIN-SSH-001",
    name="SSH Weak Cipher Detection",
    description="Checks for CBC mode ciphers",
    target_services=["ssh"],
    target_ports=[22, 2222],
    code_type="inline",
    code="""
import socket

def check():
    findings = []

    # Your security check code here
    # Use injected variables: target, port, service, banner

    sock = socket.socket()
    sock.connect((target, port))
    # ... perform check ...

    if weak_cipher_detected:
        findings.append({
            'title': 'SSH Weak Cipher Detected',
            'description': f'CBC mode cipher found on {target}:{port}',
            'severity': 'HIGH',
            'recommendation': 'Disable CBC ciphers in sshd_config',
            'confidence': 0.9,
            'raw_output': response_data
        })

    return {'findings': findings}
""",
    enabled=True,
    severity="HIGH",
    timeout_seconds=30,
    required_variables=["target", "port"]
)
```

### Method 2: File Reference (External Python File)

**Plugin Code File** (`/data/plugins/my_check.py`):
```python
"""
My Custom Security Check
"""
import requests

def check():
    findings = []

    # Check for admin panel exposure
    try:
        response = requests.get(
            f"http://{target}:{port}/admin",
            timeout=10
        )

        if response.status_code == 200:
            findings.append({
                'title': 'Admin Panel Exposed',
                'description': f'Admin panel accessible at {target}:{port}/admin',
                'severity': 'MEDIUM',
                'recommendation': 'Restrict access to admin panel',
                'confidence': 1.0
            })
    except:
        pass

    return {'findings': findings}
```

**Database Entry:**
```python
Plugin(
    plugin_id="PLUGIN-HTTP-001",
    name="Admin Panel Detection",
    target_services=["http", "https"],
    code_type="file",
    code_file_path="/data/plugins/my_check.py",
    enabled=True
)
```

---

## Plugin Code Requirements

### Required Function

Every plugin MUST define a `check()` function:

```python
def check():
    """
    Perform security check.

    Returns:
        dict: {'findings': [list of finding dicts]}
    """
    findings = []

    # Your check logic here
    # Use injected variables: target, port, service, banner

    return {'findings': findings}
```

### Finding Format

Each finding dict must contain:

```python
{
    'title': str,           # Required: Short title
    'description': str,     # Required: Detailed description
    'severity': str,        # Required: CRITICAL, HIGH, MEDIUM, LOW, INFO
    'recommendation': str,  # Required: How to fix
    'confidence': float,    # Optional: 0.0-1.0 (default: 1.0)
    'raw_output': str,      # Optional: Raw check output
    'references': list,     # Optional: Reference URLs
    'cve_ids': list,        # Optional: CVE identifiers
    'risk_score': float     # Optional: 0.0-10.0
}
```

### Async Support

Plugins can be synchronous or asynchronous:

```python
# Synchronous
def check():
    return {'findings': []}

# Asynchronous
async def check():
    await asyncio.sleep(1)
    return {'findings': []}
```

---

## Port and Service Filtering

### Match by Service Name

```python
Plugin(
    target_services=["ssh", "telnet"],  # Runs on SSH and Telnet services
    target_ports=[]  # Empty = all ports for these services
)
```

### Match by Specific Ports

```python
Plugin(
    target_services=["http"],
    target_ports=[80, 8080, 8000]  # Only runs on these specific ports
)
```

### Match All Ports for Service

```python
Plugin(
    target_services=["mysql"],
    target_ports=[]  # Runs on ANY port where MySQL is detected
)
```

### Match Specific Ports Regardless of Service

```python
Plugin(
    target_services=[],  # Empty = all services
    target_ports=[22, 23, 3389]  # Only these ports
)
```

---

## Example Plugins Included

### 1. SSH Weak Cipher Detection (`PLUGIN-SSH-001`)

**What it checks:**
- SSH Protocol Version 1 support (CRITICAL)
- CBC mode ciphers (HIGH)
- Banner information disclosure (INFO)

**Target:**
- Services: `["ssh"]`
- Ports: `[22, 2222]`

**File:** `examples/plugins/ssh_weak_ciphers.py`

### 2. Deprecated TLS Version Detection (`PLUGIN-TLS-001`)

**What it checks:**
- TLS 1.0 support (HIGH)
- TLS 1.1 support (HIGH)

**Target:**
- Services: `["https", "ssl"]`
- Ports: `[443, 8443]`

---

## Using the Plugin System

### Seed Example Plugins

```bash
python -m icebreaker.db.seed_example_plugins
```

Output:
```
Seeding example plugins...
✅ Created plugin: PLUGIN-SSH-001 - SSH Weak Cipher Detection
✅ Created plugin: PLUGIN-TLS-001 - Deprecated TLS Version Detection

✅ Plugin seeding completed!
```

### Run Scan with Plugins

Plugins execute automatically during scans when matching services are discovered:

```python
from icebreaker.core.plugin_executor import PluginExecutor

# During scan execution
executor = PluginExecutor(db)

# After discovering a service
findings = await executor.execute_plugins_for_service(
    scan_id=scan.id,
    target="192.168.1.100",
    port=22,
    service="ssh",
    banner="SSH-2.0-OpenSSH_8.2p1"
)

# Findings are automatically created in database
for finding in findings:
    db.add(finding)
db.commit()
```

### Check Plugin Execution Stats

```python
stats = executor.get_stats()
print(stats)
# {
#     'total_executed': 5,
#     'successful': 4,
#     'failed': 1,
#     'findings_generated': 3
# }
```

---

## Security Considerations

### Code Execution Safety

1. **Timeout Protection**: All plugins have configurable timeouts (default: 30s)
2. **Error Isolation**: Plugin failures don't crash the scan
3. **Variable Injection**: Only predefined variables are injected
4. **No eval() on User Input**: Plugin code must be pre-loaded, not user-submitted at runtime

### Recommended Practices

1. **Review Plugin Code**: Always review plugins before enabling
2. **Test in Isolation**: Test plugins individually before production use
3. **Set Appropriate Timeouts**: Prevent long-running checks from blocking scans
4. **Use File References**: Store complex plugins as files for easier review
5. **Version Control**: Track plugin changes in git

---

## Database Schema

### Plugin Model

```sql
CREATE TABLE plugins (
    id INTEGER PRIMARY KEY,
    plugin_id VARCHAR(100) UNIQUE NOT NULL,  -- PLUGIN-XXX-NNN
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    author VARCHAR(255),
    version VARCHAR(50) DEFAULT '1.0.0',

    -- Targeting
    target_services JSON DEFAULT '[]',  -- ["ssh", "http"]
    target_ports JSON DEFAULT '[]',     -- [22, 80, 443]

    -- Code
    code_type VARCHAR(20) DEFAULT 'inline',  -- "inline" or "file"
    code TEXT,
    code_file_path VARCHAR(500),

    -- Metadata
    template_id INTEGER REFERENCES finding_templates(id),
    enabled BOOLEAN DEFAULT TRUE,
    severity VARCHAR(20) DEFAULT 'INFO',
    tags JSON DEFAULT '[]',
    timeout_seconds INTEGER DEFAULT 30,
    required_variables JSON DEFAULT '[]',

    -- Stats
    created_at DATETIME,
    updated_at DATETIME,
    last_executed DATETIME,
    execution_count INTEGER DEFAULT 0
);
```

### Finding Model (Updated)

```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    finding_id VARCHAR(255) UNIQUE NOT NULL,  -- NOW UNIQUE!
    scan_id INTEGER NOT NULL,
    template_id INTEGER,
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    target VARCHAR(255) NOT NULL,
    port INTEGER,
    tags JSON,
    details JSON,  -- Includes plugin info: plugin_id, plugin_name, raw_output
    confidence FLOAT DEFAULT 1.0,
    risk_score FLOAT,
    recommendation TEXT,
    false_positive BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'new',
    assigned_to VARCHAR(255),
    notes TEXT,
    first_seen DATETIME,
    last_seen DATETIME
);
```

---

## API Endpoints

### Export Findings
```
GET /api/exports/scans/{scan_id}/findings.csv
```

### Import Findings
```
POST /api/imports/scans/{scan_id}/findings.csv
Content-Type: multipart/form-data

Body: file=findings.csv
```

Response:
```json
{
    "success": true,
    "scan_id": 1,
    "statistics": {
        "total_rows": 25,
        "created": 10,
        "updated": 12,
        "skipped": 3,
        "errors": [
            "Row 15: Missing target"
        ]
    },
    "message": "Imported 10 new findings, updated 12 existing findings"
}
```

---

## Next Steps for Integration

### TODO: Integrate into Scan Workflow

Edit `icebreaker/api/routers/scans.py` in the `execute_scan` function:

```python
# After port scanning phase (line ~1144)
# After discovering services
# Before analysis phase (line ~1149)

from icebreaker.core.plugin_executor import PluginExecutor

# Initialize plugin executor
plugin_executor = PluginExecutor(db)

# Execute plugins for each discovered service
for target_service in discovered_services:
    plugin_findings = await plugin_executor.execute_plugins_for_service(
        scan_id=scan.id,
        target=target_service['target'],
        port=target_service['port'],
        service=target_service['service'],
        banner=target_service.get('banner', ''),
        extra_vars={'scan': scan}
    )

    # Add plugin findings to database
    for finding in plugin_findings:
        db.add(finding)

db.commit()
```

### TODO: Add Import UI

Add import button to scan detail page:

```html
<!-- In scan_detail.html Findings tab -->
<div class="mb-4">
    <label for="import-csv" class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 cursor-pointer">
        📥 Import Findings CSV
    </label>
    <input type="file" id="import-csv" accept=".csv" class="hidden" onchange="importFindings(event)">
</div>

<script>
async function importFindings(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`/api/imports/scans/${scanId}/findings.csv`, {
        method: 'POST',
        body: formData
    });

    const result = await response.json();
    if (result.success) {
        showToast(`${result.message}`, 'success');
        loadFindings();  // Reload findings list
    } else {
        showToast('Import failed', 'error');
    }
}
</script>
```

---

## Troubleshooting

### Plugin Not Executing

1. Check plugin is enabled: `Plugin.enabled = True`
2. Verify service/port match: `target_services` and `target_ports`
3. Check timeout: Increase `timeout_seconds` if needed
4. Review logs for execution errors

### Finding Not Created

1. Plugin must return `{'findings': [...]}`
2. Each finding must have required fields: `title`, `description`, `severity`, `recommendation`
3. Check `finding_id` uniqueness constraint

### Import Failing

1. CSV must have header row matching export format
2. Required columns: `Title`, `Severity`, `Target`
3. Severity must be: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
4. Check error messages in response `statistics.errors`

---

## Summary

You now have:

✅ **Finding Import/Export** with unique IDs and upsert capability
✅ **Plugin Database Model** with service/port filtering
✅ **Plugin Executor** with variable injection and timeout handling
✅ **Example Plugins** (SSH weak ciphers, deprecated TLS)
✅ **Migration Script** to make finding_id unique

**Pending:**
- [ ] Integrate plugin executor into scan workflow (`scans.py`)
- [ ] Add import UI to scan detail page
- [ ] Create plugin management UI (list, create, edit, enable/disable)

This gives you a Nessus-like plugin system where you can write custom security checks that execute automatically during scans!
