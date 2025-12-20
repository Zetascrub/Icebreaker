# Analyzer to Plugin Migration

## What Changed?

All built-in analyzers have been converted to **plugins** that can be managed through the plugin system. This gives you full control over what checks run during scans.

### Before (Hardcoded Analyzers):
- ❌ Analyzers ran automatically on every scan
- ❌ No way to disable specific analyzers
- ❌ No way to customize analyzer behavior
- ❌ Analyzers were hardcoded in Python

### After (Plugin-Based):
- ✅ All analyzers are now plugins
- ✅ Enable/disable any analyzer via web UI or API
- ✅ Customize analyzer behavior by editing plugin code
- ✅ Add custom analyzers easily
- ✅ Full control over what runs

## Migration Steps

### 1. Seed Analyzer Plugins (One-Time Setup)

Run this command to convert all built-in analyzers to plugins:

```bash
# Docker
docker exec icebreaker-web python -m icebreaker.db.seed_analyzer_plugins /data/icebreaker.db

# Local
python -m icebreaker.db.seed_analyzer_plugins data/icebreaker.db
```

This creates the following plugins:
- `ANALYZER-HTTP-001` - HTTP Basic Analyzer
- `ANALYZER-SECURITY-HEADERS-001` - Security Headers Analyzer
- `ANALYZER-TLS-001` - TLS/SSL Analyzer
- `ANALYZER-INFO-DISCLOSURE-001` - Information Disclosure Analyzer
- `ANALYZER-SSH-001` - SSH Banner Analyzer

### 2. Verify Plugins Are Loaded

Visit http://localhost:8000/plugins or use the API:

```bash
curl http://localhost:8000/api/plugins | jq
```

You should see all 5 analyzer plugins with `"enabled": true`.

### 3. Run a Scan

Scans now use **only** the plugin system. The hardcoded analyzer execution has been removed.

```bash
# Via web UI
http://localhost:8000/scans/new

# Via CLI
icebreaker -t example.com --ports 80,443
```

## Managing Analyzer Plugins

### Enable/Disable via Web UI

1. Go to http://localhost:8000/plugins
2. Click on any analyzer plugin
3. Toggle "Enabled" switch
4. Changes take effect immediately for new scans

### Enable/Disable via API

```bash
# Disable HTTP analyzer
curl -X POST http://localhost:8000/api/plugins/1/toggle

# List only enabled plugins
curl http://localhost:8000/api/plugins?enabled_only=true
```

### Customize Analyzer Behavior

Edit the plugin code directly via the API:

```bash
# Get plugin with code
curl http://localhost:8000/api/plugins/1 | jq '.code'

# Update plugin code
curl -X PUT http://localhost:8000/api/plugins/1 \
  -H "Content-Type: application/json" \
  -d '{"code": "your updated code here"}'
```

## Creating Custom Analyzers

All analyzer plugins follow the same pattern:

```python
# Your analyzer code
# Variables available: target, port, service, banner
import httpx

async def check():
    findings = []

    try:
        # IMPORTANT: Use the injected 'service' variable, NOT hardcoded conditions
        # The 'service' variable will be set based on your plugin's Target Services config
        # For example, if Target Services = ["http", "https"], service will be "http" or "https"

        # ✅ GOOD: Use the service variable
        use_https = service.lower() == "https"

        # ❌ BAD: Don't hardcode port checks - plugin already filtered by Target Ports
        # use_https = port == 443  # Don't do this!

        base_url = f"{'https' if use_https else 'http'}://{target}:{port}"

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(base_url)

            # Add your custom checks here
            if some_condition:
                findings.append({
                    'title': 'Your Finding Title',
                    'severity': 'HIGH',  # CRITICAL, HIGH, MEDIUM, LOW, INFO
                    'description': 'Detailed description',
                    'recommendation': 'How to fix',
                    'references': ['CVE-2024-1234']  # Optional
                })
    except:
        pass

    return {'findings': findings}
```

### Plugin Code Requirements:

**IMPORTANT:** All plugin code must define a `check()` function that returns `{'findings': [list]}`:

- Use `async def check():` if your code uses async libraries (httpx, asyncio, etc.)
- Use `def check():` if your code is synchronous (socket, ssl, etc.)

### Best Practices:

**✅ DO:**
- Define a `check()` function (async or sync depending on your code)
- Use injected variables: `target`, `port`, `service`, `banner`
- Trust the plugin filtering (Target Services/Ports) - your code only runs if matched
- Check the `service` variable to determine protocol: `if service.lower() == "https"`
- Return `{'findings': [list]}` from your check() function

**❌ DON'T:**
- Hardcode port numbers: ~~`if port == 443`~~ (plugin already filtered this!)
- Hardcode service names: ~~`if "http" in banner`~~ (use `service` variable instead)
- Add redundant checks - the plugin system handles targeting
- Forget to wrap code in a `check()` function - it will fail!

Then create the plugin via API:

```bash
curl -X POST http://localhost:8000/api/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_id": "CUSTOM-ANALYZER-001",
    "name": "My Custom Analyzer",
    "description": "Checks for custom vulnerabilities",
    "target_services": ["http", "https"],
    "code_type": "inline",
    "code": "your code here",
    "enabled": true,
    "severity": "MEDIUM",
    "timeout_seconds": 15
  }'
```

## Benefits

### 1. **User Control**
Users can now disable noisy or irrelevant analyzers for their environment.

### 2. **Customization**
Modify existing analyzer logic without changing source code.

### 3. **Extensibility**
Add custom analyzers specific to your infrastructure.

### 4. **Performance**
Disable unused analyzers to speed up scans.

### 5. **Auditability**
All analyzer execution is logged with plugin IDs in findings.

## Troubleshooting

### No Findings After Migration?

Check if analyzer plugins are enabled:
```bash
curl http://localhost:8000/api/plugins | jq '.[] | select(.enabled == true) | .name'
```

If empty, run the seed script again:
```bash
python -m icebreaker.db.seed_analyzer_plugins
```

### Plugins Not Executing?

Check scan logs:
```bash
docker logs icebreaker-web -f | grep -i plugin
```

Look for:
```
Scan 1: Executing plugins for 5 services
Scan 1: Plugin stats - Executed: 10, Success: 10, Failed: 0, Findings: 8
```

### Want to Revert to Old Analyzers?

The old analyzer code still exists in `icebreaker/analyzers/`. You can re-enable them by uncommenting the analyzer setup in `icebreaker/api/routers/scans.py` around line 1088.

## Summary

✅ All analyzers are now plugins
✅ Full user control via web UI and API
✅ Customizable without code changes
✅ Easy to extend with custom checks
✅ Backward compatible (old analyzers still in codebase)

For more details, see [docs/PLUGIN_SYSTEM.md](docs/PLUGIN_SYSTEM.md).
