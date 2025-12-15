# Nessus Plugin Import - Quick Start

## TL;DR

```bash
# 1. Preview first (recommended)
icebreaker import nessus all-2.0.tar.gz --preview

# 2. If encrypted, decrypt with Nessus
/opt/nessus/sbin/nessuscli update all-2.0.tar.gz

# 3. Import decrypted plugins
tar -czf plugins.tar.gz -C /opt/nessus/lib/nessus/plugins *.nasl
icebreaker import nessus plugins.tar.gz

# 4. Or use sample plugins for testing
icebreaker import nessus /tmp/sample_nasl_plugins/sample_plugins.tar.gz
```

## Problem: Encrypted Archive

**Error:**
```
Error: Invalid tar archive: not a gzip file
Note: If this is an encrypted Nessus plugin feed, you need to decrypt it first
```

**Solution:**

### Option 1: Use Nessus to Decrypt
```bash
# Install Nessus first
wget https://www.tenable.com/downloads/nessus
sudo dpkg -i Nessus-*.deb
sudo systemctl start nessusd

# Decrypt plugins
/opt/nessus/sbin/nessuscli update /path/to/all-2.0.tar.gz

# Export decrypted plugins
cd /opt/nessus/lib/nessus/plugins
tar -czf ~/nessus_plugins_decrypted.tar.gz *.nasl

# Import into Icebreaker
icebreaker import nessus ~/nessus_plugins_decrypted.tar.gz
```

### Option 2: Use GPL Plugins (Free, No Decryption Needed)
```bash
# Download GPL plugins (already decrypted)
wget https://www.nessus.org/nasl/all-2.0.tar.gz -O nessus_gpl.tar.gz

# Import
icebreaker import nessus nessus_gpl.tar.gz
```

### Option 3: Use Sample Plugins (Testing Only)
```bash
# Sample plugins already created at:
ls /tmp/sample_nasl_plugins/

# Import for testing
cd /tmp/sample_nasl_plugins
tar -czf sample_plugins.tar.gz *.nasl
icebreaker import nessus sample_plugins.tar.gz
```

## Quick Commands

```bash
# Preview 100 plugins
icebreaker import nessus plugins.tar.gz --preview --sample 100

# Import all
icebreaker import nessus plugins.tar.gz

# Custom database
icebreaker import nessus plugins.tar.gz --db /custom/path/db.sqlite

# Via web API
curl -X POST http://localhost:8000/api/import/nessus \
  -F "file=@plugins.tar.gz"
```

## What You Get

Each imported plugin becomes a **Finding Template** with:

- ✅ Vulnerability title and description
- ✅ Severity rating (Critical/High/Medium/Low/Info)
- ✅ CVSS v2 and v3 scores
- ✅ CVE identifiers
- ✅ CWE classification
- ✅ Detailed remediation steps
- ✅ Reference links

## Verify Import

```bash
# Check database
sqlite3 data/icebreaker.db "SELECT COUNT(*) FROM finding_templates;"

# Or via web UI
icebreaker-web
# Navigate to: Settings > Finding Templates
```

## Common Issues

| Issue | Solution |
|-------|----------|
| "not a gzip file" | Archive is encrypted, use nessuscli to decrypt |
| "No .nasl files found" | Check archive with `tar -tzf file.tar.gz` |
| "Module not found" | Install: `pip install -e .` |
| Import stuck | Check logs: `tail -f data/icebreaker.log` |

## Performance

- **Small (1K plugins):** ~30 seconds
- **Medium (10K plugins):** ~5 minutes
- **Large (100K+ plugins):** ~45 minutes

Use preview mode first for large imports!

## Next Steps

After import:
1. ✅ Templates are in database
2. ✅ Ready to use during scans
3. ✅ Auto-link findings to templates
4. ✅ Get enriched reports with remediation

See [NESSUS_IMPORT.md](../NESSUS_IMPORT.md) for complete documentation.
