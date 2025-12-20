# Nessus Plugin Import Guide

This guide explains how to import Nessus vulnerability plugins into Icebreaker.

## Overview

Icebreaker can import Nessus NASL (Nessus Attack Scripting Language) plugins and convert them into finding templates. These templates can then be used during scans to provide standardized vulnerability descriptions, remediation steps, and risk scoring.

## What Gets Imported

From each NASL plugin, Icebreaker extracts:

- **Title** - Vulnerability name
- **Description** - Detailed vulnerability description
- **Severity** - Risk level (Critical, High, Medium, Low, Info)
- **CVSS Score** - Both v2 and v3 scores
- **CVE IDs** - Associated CVE identifiers
- **CWE** - Common Weakness Enumeration
- **Solution/Remediation** - Fix recommendations
- **References** - Additional resources and links
- **Category/Family** - Plugin classification

## Import Methods

### 1. CLI Import (Recommended)

```bash
# Preview plugins before importing (recommended first step)
icebreaker import nessus all-2.0.tar.gz --preview --sample 50

# Import all plugins
icebreaker import nessus all-2.0.tar.gz

# Import with custom database path
icebreaker import nessus plugins.tar.gz --db /path/to/custom.db
```

**CLI Options:**
- `--preview` - Preview mode, shows sample plugins without importing
- `--sample N` - Number of plugins to show in preview (default: 20)
- `--db PATH` - Custom database path (default: data/icebreaker.db)

### 2. Web API Import

The web interface provides import functionality with a two-step process:

**Step 1: Preview**
```bash
curl -X POST http://localhost:8000/api/import/nessus/preview \
  -F "file=@all-2.0.tar.gz" \
  -F "sample_size=20"
```

Response includes:
- Total files in archive
- Sample plugin data
- Estimated valid/invalid counts
- Duplicate detection
- Preview ID for confirmation

**Step 2: Confirm Import**
```bash
curl -X POST http://localhost:8000/api/import/nessus/confirm/{preview_id}
```

**Step 3: Check Status**
```bash
curl http://localhost:8000/api/import/status/{job_id}
```

**Alternative: Direct Import** (skips preview)
```bash
curl -X POST http://localhost:8000/api/import/nessus \
  -F "file=@all-2.0.tar.gz"
```

## Obtaining Nessus Plugins

### Official Sources

1. **Tenable Official Feed** (requires registration)
   - URL: https://plugins.nessus.org/
   - File: `all-2.0.tar.gz`
   - Note: Files are encrypted and require Nessus installation

2. **GPL Plugins** (free, limited)
   - URL: https://www.nessus.org/nasl/
   - File: `all-2.0.tar.gz`
   - Contains only GPL-licensed plugins

### Decrypting Encrypted Plugin Feeds

If you have an encrypted `all-2.0.tar.gz` file from Tenable:

```bash
# Using nessuscli (requires Nessus installation)
/opt/nessus/sbin/nessuscli update all-2.0.tar.gz

# This will decrypt and install plugins to:
# /opt/nessus/lib/nessus/plugins/

# You can then create a tar from the decrypted files:
cd /opt/nessus/lib/nessus/plugins/
tar -czf ~/nessus_plugins_decrypted.tar.gz *.nasl
```

**Alternative: Extract from Nessus Installation**

If you have a working Nessus installation:

```bash
# Find plugins directory
find /opt/nessus -name "*.nasl" -type f | head -5

# Create archive from existing plugins
tar -czf nessus_plugins.tar.gz -C /opt/nessus/lib/nessus/plugins .
```

## Troubleshooting

### "Invalid tar archive" or "not a gzip file"

This means your `all-2.0.tar.gz` is encrypted. You need to:

1. Install Nessus
2. Use `nessuscli update` to decrypt the feed
3. Extract the decrypted .nasl files
4. Create a new tar.gz archive

### "No .nasl files found in archive"

Check the archive contents:

```bash
tar -tzf all-2.0.tar.gz | head -20
```

The archive should contain `.nasl` files. If you see binary data or no files, the archive is encrypted.

### Import Progress Tracking

For large plugin sets (10,000+ plugins), use the web API with job status monitoring:

```bash
# Start import
RESPONSE=$(curl -X POST http://localhost:8000/api/import/nessus -F "file=@plugins.tar.gz")
JOB_ID=$(echo $RESPONSE | jq -r '.job_id')

# Monitor progress
watch -n 2 "curl -s http://localhost:8000/api/import/status/$JOB_ID | jq ."
```

## Database Schema

Imported plugins are stored in the `finding_templates` table:

```sql
CREATE TABLE finding_templates (
    id INTEGER PRIMARY KEY,
    finding_id VARCHAR(100) UNIQUE,  -- e.g., "NESSUS-12345"
    title VARCHAR(500),
    category VARCHAR(100),
    description TEXT,
    impact TEXT,
    remediation TEXT,
    severity VARCHAR(20),
    cvss_score FLOAT,
    cvss_vector VARCHAR(255),
    cwe_id VARCHAR(50),
    references JSON,
    enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME,
    updated_at DATETIME
);
```

## Using Imported Templates During Scans

Once imported, templates are automatically linked to findings during scans:

1. **Analyzer detects vulnerability** (e.g., weak SSL cipher)
2. **Match to template** by finding_id or title
3. **Enrich finding** with template data:
   - Standardized description
   - Detailed remediation steps
   - CVE/CWE references
   - CVSS scoring

Example in analyzer code:

```python
from icebreaker.db.database import SessionLocal
from icebreaker.db.models import FindingTemplate

def analyze_ssl(target, port):
    finding = Finding(
        id="weak-ssl-cipher",
        title="SSL Weak Cipher Suite Detected",
        target=target,
        port=port
    )

    # Link to template for enrichment
    db = SessionLocal()
    template = db.query(FindingTemplate).filter(
        FindingTemplate.finding_id == "NESSUS-ssl_weak_ciphers"
    ).first()

    if template:
        finding.template_id = template.id
        finding.recommendation = template.remediation

    return finding
```

## Performance Considerations

**Import Times:**
- 1,000 plugins: ~30 seconds
- 10,000 plugins: ~5 minutes
- 100,000+ plugins: ~45 minutes

**Database Size:**
- ~1,000 plugins: ~5 MB
- ~10,000 plugins: ~50 MB
- ~100,000 plugins: ~500 MB

**Optimization Tips:**
- Use preview mode first to validate archive
- Import runs in background (web API)
- Batch commits every 100 plugins
- Duplicates are updated, not duplicated

## Example: Complete Import Workflow

```bash
# 1. Preview the archive
icebreaker import nessus all-2.0.tar.gz --preview --sample 100

# Expected output:
# Found 125,432 NASL plugin files
# Previewing 100 plugins...
#   ✓ SSH Server Weak Algorithm Support [MEDIUM]
#   ✓ SSL/TLS Weak Cipher Suites [HIGH]
#   ...
# Preview Summary:
#   Valid plugins: 95/100
#   Estimated total valid: ~119,160

# 2. If preview looks good, import
icebreaker import nessus all-2.0.tar.gz

# Expected output:
# Importing Nessus plugins from: all-2.0.tar.gz
# Extracting archive...
# Found 125,432 NASL plugin files
# Initializing database...
# Importing plugins... ████████████████████ 100%
#
# Import Complete!
#   New templates: 118,945
#   Updated templates: 0
#   Skipped: 6,487
#   Errors: 0

# 3. Verify import
icebreaker-web
# Navigate to Settings > Finding Templates
# You should see all imported templates
```

## API Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/import/nessus/preview` | POST | Preview plugins before import |
| `/api/import/nessus/confirm/{preview_id}` | POST | Confirm and execute import |
| `/api/import/nessus` | POST | Direct import (skip preview) |
| `/api/import/status/{job_id}` | GET | Check import job status |
| `/api/import/jobs` | GET | List all import jobs |
| `/api/import/jobs/{job_id}` | DELETE | Delete import job |
| `/api/import/preview/{preview_id}` | DELETE | Cancel preview |

## Sample NASL Files

For testing purposes, sample NASL files are included in `/tmp/sample_nasl_plugins/`:

- `ssh_weak_algorithms.nasl` - SSH weak crypto detection
- `ssl_weak_ciphers.nasl` - SSL/TLS weak ciphers
- `apache_outdated.nasl` - Outdated Apache HTTP Server

Test with:
```bash
cd /tmp/sample_nasl_plugins
tar -czf test_plugins.tar.gz *.nasl
icebreaker import nessus test_plugins.tar.gz --preview
```

## Additional Resources

- Nessus NASL Reference: https://docs.tenable.com/nessus/Content/NASL.htm
- Tenable Plugin Portal: https://www.tenable.com/plugins
- CVE Database: https://nvd.nist.gov/
- CWE Database: https://cwe.mitre.org/

## Support

For issues with import functionality:

1. Check the logs: `data/icebreaker.log`
2. Verify archive format: `tar -tzf all-2.0.tar.gz | head`
3. Try preview mode first: `--preview --sample 50`
4. Report issues: https://github.com/Zetascrub/Icebreaker/issues
