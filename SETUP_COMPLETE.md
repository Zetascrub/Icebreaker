# ✅ Icebreaker Plugin System - Setup Complete!

## What's Been Installed

### 1. Finding Import/Export System
- ✅ CSV export with all finding data
- ✅ CSV import with upsert (update existing or create new)
- ✅ Unique `finding_id` constraint in database
- ✅ UI buttons in scan detail page (Findings tab)

### 2. Plugin-Based Vulnerability Detection
- ✅ Plugin database model
- ✅ Plugin executor with variable injection
- ✅ Integrated into scan workflow
- ✅ 2 example plugins seeded:
  - **PLUGIN-SSH-001**: SSH Weak Cipher Detection
  - **PLUGIN-TLS-001**: Deprecated TLS Version Detection
- ✅ Plugin management API

---

## Migration Status

```
✅ Database tables created
✅ finding_id unique constraint added
✅ No duplicate finding_ids found
✅ Example plugins seeded
```

---

## How to Test

### Test 1: Run a Scan with Plugins

1. Start Icebreaker:
   ```bash
   docker-compose up -d
   # or
   python -m icebreaker.cli scan --targets <your-target>
   ```

2. Navigate to: `http://localhost:9000/scans/new`

3. Add targets with SSH or HTTPS services:
   - SSH: `example.com`, `192.168.1.1` (port 22)
   - HTTPS: `google.com`, `example.com` (port 443)

4. Click "Start Scan"

5. Watch for plugin execution in logs:
   ```
   Scan 1: Executing plugins for 3 services
   Scan 1: Plugins generated 1 findings
   Scan 1: Plugin stats - Executed: 3, Success: 3, Failed: 0, Findings: 1
   ```

6. Go to scan detail page → **Findings** tab

7. Look for plugin-generated findings:
   - "SSH Server Supports Weak Ciphers"
   - "Deprecated TLS 1.0 Protocol Supported"

### Test 2: Export/Import Findings

1. Go to any scan with findings

2. Click **⬇ Export CSV** button

3. Open the CSV file in Excel/LibreOffice

4. Make changes:
   - Change severity from HIGH to CRITICAL
   - Update the title
   - Change status from "new" to "confirmed"

5. Save the CSV

6. Go back to the scan detail page

7. Click **⬆ Import CSV** button

8. Select your modified CSV

9. You'll see:
   ```
   Import complete: 0 created, 5 updated, 0 skipped
   ```

10. Page reloads with updated findings!

### Test 3: View Plugins via API

```bash
# List all plugins
curl http://localhost:9000/api/plugins | jq

# Get specific plugin
curl http://localhost:9000/api/plugins/1 | jq

# Disable a plugin
curl -X POST http://localhost:9000/api/plugins/1/toggle

# List again to see it's disabled
curl http://localhost:9000/api/plugins | jq
```

---

## File Locations

**Database:**
- `/data/icebreaker.db` (Docker)
- `./icebreaker.db` (local)

**Plugin Code:**
- Inline: Stored in `plugins.code` column
- File: `/data/plugins/your_plugin.py`

**Example Plugins:**
- `examples/plugins/ssh_weak_ciphers.py`

**Documentation:**
- `PLUGIN_SYSTEM.md` - Full technical documentation
- `QUICK_START_PLUGINS.md` - Quick start guide
- `SETUP_COMPLETE.md` - This file

---

## Example Plugin Output

When you run a scan against an SSH server, you might see findings like:

```
Finding: SSH Server Supports Weak Ciphers
Severity: HIGH
Target: 192.168.1.100:22
Description: The SSH server supports deprecated CBC mode ciphers: cbc, 3des.
             CBC mode ciphers are vulnerable to plaintext recovery attacks.
Recommendation: Disable CBC mode ciphers in sshd_config. Use only secure
                ciphers like chacha20-poly1305@openssh.com, aes256-gcm@openssh.com
Confidence: 0.7
Plugin: PLUGIN-SSH-001 v1.0.0
```

---

## Creating Your First Custom Plugin

### Step 1: Write the Plugin Code

Create `/data/plugins/redis_check.py`:

```python
"""Check for open Redis instances"""
import socket

def check():
    findings = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.sendall(b"PING\r\n")
        response = sock.recv(1024).decode()
        sock.close()

        if "+PONG" in response:
            findings.append({
                'title': 'Unauthenticated Redis Access',
                'description': f'Redis at {target}:{port} accepts commands without auth',
                'severity': 'CRITICAL',
                'recommendation': 'Enable requirepass in redis.conf',
                'confidence': 1.0
            })
    except:
        pass

    return {'findings': findings}
```

### Step 2: Add to Database

```bash
curl -X POST http://localhost:9000/api/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_id": "PLUGIN-REDIS-001",
    "name": "Open Redis Detection",
    "description": "Detects unauthenticated Redis instances",
    "author": "Your Name",
    "target_services": ["redis"],
    "target_ports": [6379],
    "code_type": "file",
    "code_file_path": "/data/plugins/redis_check.py",
    "enabled": true,
    "severity": "CRITICAL",
    "timeout_seconds": 30
  }'
```

### Step 3: Test It

Run a scan against a target with Redis on port 6379, and your plugin will execute automatically!

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/plugins` | List all plugins |
| GET | `/api/plugins/{id}` | Get plugin details with code |
| POST | `/api/plugins` | Create new plugin |
| PUT | `/api/plugins/{id}` | Update plugin |
| DELETE | `/api/plugins/{id}` | Delete plugin |
| POST | `/api/plugins/{id}/toggle` | Enable/disable plugin |
| GET | `/api/exports/scans/{id}/findings.csv` | Export findings |
| POST | `/api/imports/scans/{id}/findings.csv` | Import findings |

---

## Troubleshooting

### Plugins Not Executing?

Check:
1. Plugin is enabled: `curl http://localhost:9000/api/plugins | jq '.[] | select(.enabled==true)'`
2. Service name matches: Plugin targets "ssh" but service detected as "SSH" (case-sensitive)
3. Check logs: `docker logs icebreaker-web | grep -i plugin`

### Import Fails?

Check CSV format:
- Must have header row
- Required columns: `Finding ID`, `Title`, `Severity`, `Target`
- Severity values: CRITICAL, HIGH, MEDIUM, LOW, INFO (uppercase)

### Want to Reset?

```bash
# Stop containers
docker-compose down

# Remove database
rm /data/icebreaker.db  # or ./icebreaker.db

# Restart
docker-compose up -d

# Re-run migration and seed
python -m icebreaker.db.migrate_unique_finding_id
python -m icebreaker.db.seed_example_plugins
```

---

## What's Next?

1. **Run your first scan** with the example plugins
2. **Test the import/export** workflow
3. **Create a custom plugin** for your specific needs
4. **Build a plugin management UI** (optional - API works great!)
5. **Share your plugins** with the community

---

## Summary

You now have a fully functional Nessus-style plugin system where:

✅ Plugins execute automatically during scans
✅ Findings can be exported, edited, and re-imported
✅ Custom vulnerability checks are easy to create
✅ Everything is managed via a REST API

**Happy Scanning!** 🎉

For more details, see:
- `PLUGIN_SYSTEM.md` - Complete technical documentation
- `QUICK_START_PLUGINS.md` - Quick reference guide
