# Quick Command Reference

## Setup Commands (Run Once)

```bash
# Activate virtual environment
. .venv/bin/activate

# Run database migration
python -m icebreaker.db.migrate_unique_finding_id

# Seed example plugins
python -m icebreaker.db.seed_example_plugins

# Start Icebreaker
docker-compose up -d
```

## Plugin Management

```bash
# List all plugins
curl http://localhost:9000/api/plugins | jq

# List only enabled plugins
curl http://localhost:9000/api/plugins?enabled_only=true | jq

# Get plugin details (including code)
curl http://localhost:9000/api/plugins/1 | jq

# Enable/disable plugin
curl -X POST http://localhost:9000/api/plugins/1/toggle

# Create new plugin
curl -X POST http://localhost:9000/api/plugins \
  -H "Content-Type: application/json" \
  -d @plugin.json

# Update plugin
curl -X PUT http://localhost:9000/api/plugins/1 \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete plugin
curl -X DELETE http://localhost:9000/api/plugins/1
```

## Finding Import/Export

```bash
# Export findings as CSV
curl http://localhost:9000/api/exports/scans/1/findings.csv > findings.csv

# Import findings (from web UI - use the upload button)
# Or via curl:
curl -X POST http://localhost:9000/api/imports/scans/1/findings.csv \
  -F "file=@findings.csv"
```

## Testing & Debugging

```bash
# View logs
docker logs icebreaker-web -f

# Filter for plugin-related logs
docker logs icebreaker-web 2>&1 | grep -i plugin

# Check database
sqlite3 /data/icebreaker.db "SELECT * FROM plugins;"
sqlite3 /data/icebreaker.db "SELECT finding_id, title, severity FROM findings;"

# Test API health
curl http://localhost:9000/health
```

## Example: Create Custom Plugin

```bash
# 1. Create plugin file
cat > /data/plugins/custom.py << 'EOF'
def check():
    findings = []
    # Your check logic here using: target, port, service, banner
    return {'findings': findings}
EOF

# 2. Register plugin
curl -X POST http://localhost:9000/api/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_id": "PLUGIN-CUSTOM-001",
    "name": "My Custom Check",
    "description": "Custom vulnerability check",
    "target_services": ["http"],
    "target_ports": [80, 8080],
    "code_type": "file",
    "code_file_path": "/data/plugins/custom.py",
    "enabled": true,
    "severity": "MEDIUM",
    "timeout_seconds": 30
  }'

# 3. Verify it was created
curl http://localhost:9000/api/plugins | jq '.[] | select(.plugin_id=="PLUGIN-CUSTOM-001")'
```

## Common Tasks

```bash
# Start a scan from CLI
python -m icebreaker.cli scan --targets 192.168.1.1 example.com

# View all scans
curl http://localhost:9000/api/scans | jq

# Get scan details
curl http://localhost:9000/api/scans/1 | jq

# Get findings for scan
curl http://localhost:9000/api/scans/1/findings | jq

# Export findings in different formats
curl http://localhost:9000/api/exports/scans/1/findings.csv
curl http://localhost:9000/api/exports/scans/1/findings.json
curl http://localhost:9000/api/exports/scans/1/findings.md
curl http://localhost:9000/api/exports/scans/1/findings.sarif
```

## Useful Queries

```bash
# Count findings by severity
curl http://localhost:9000/api/scans/1/findings | \
  jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'

# List all plugin-generated findings
curl http://localhost:9000/api/scans/1/findings | \
  jq '.[] | select(.details.plugin_id != null) | {title, severity, plugin: .details.plugin_id}'

# Get execution stats for all plugins
curl http://localhost:9000/api/plugins | \
  jq '.[] | {name, enabled, execution_count, last_executed}'
```
