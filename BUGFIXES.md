# Bug Fixes

## Fixed in This Session

### 1. Dashboard and Network Map Not Loading (CSP Issue)

**Issue**: Dashboard showing no stats ("-" placeholders) and network map not rendering

**Root Cause**: Content Security Policy (CSP) header was too restrictive and blocked external CDN scripts:
- Dashboard uses Chart.js from `https://cdn.jsdelivr.net`
- Network Map uses vis-network from `https://unpkg.com`

**Fix**: Updated CSP in [icebreaker/api/app.py:59](icebreaker/api/app.py:59) to whitelist required CDN domains:

```python
# Before (blocked CDN scripts):
"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com"

# After (allows required CDNs):
"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com"
```

**Verification**:
```bash
curl -I http://localhost:9000/ | grep -i content-security-policy
```

Should show Chart.js and vis-network CDNs in the `script-src` directive.

---

### 2. Rescan Endpoint NameError

**Issue**: POST `/api/scans/{scan_id}/rescan` returned 500 error:
```
NameError: name 'run_scan_background' is not defined
```

**Root Cause**: Function was renamed from `run_scan_background` to `execute_scan_sync` but rescan endpoint wasn't updated

**Fix**: Updated [icebreaker/api/routers/scans.py:429](icebreaker/api/routers/scans.py:429):

```python
# Before:
background_tasks.add_task(run_scan_background, new_scan.id)

# After:
background_tasks.add_task(execute_scan_sync, new_scan.id)
```

**Verification**:
```bash
curl -X POST http://localhost:9000/api/scans/1/rescan
```

Should return 200 with new scan details.

---

## Testing

After applying these fixes, verify functionality:

### Dashboard
1. Navigate to `http://localhost:9000/`
2. Should see:
   - Risk score (not "-")
   - Active/completed scan counts
   - Critical/high finding counts
   - Charts rendering (Severity distribution, Status, Targets, Timeline)
   - Recent scans list

### Network Map
1. Navigate to `/network-map?scan_id=1`
2. Should see:
   - Network topology visualization
   - Stats cards (hosts, services, findings)
   - Interactive network graph
   - Color-coded nodes by risk level

### Rescan
1. From scan details page, click "Re-scan"
2. Should create new scan with same settings
3. New scan should appear in scans list

---

## Browser Console Verification

Open browser developer tools (F12) and check:

1. **No CSP errors** - Should NOT see:
   ```
   Refused to load the script 'https://cdn.jsdelivr.net/...' because it violates the following Content Security Policy directive: "script-src 'self'..."
   ```

2. **API calls succeed** - Network tab should show:
   ```
   GET /api/analytics/dashboard → 200 OK
   GET /api/analytics/network-topology?scan_id=1 → 200 OK
   ```

3. **No JavaScript errors** - Console should be clean (no red errors)

---

## Related Configuration

### CSP Best Practices

Our current CSP allows:
- **script-src**: Self-hosted scripts, inline scripts (for compatibility), Tailwind/Chart.js/vis-network CDNs
- **style-src**: Self-hosted styles, inline styles (for Tailwind)
- **img-src**: Self-hosted images, data URIs (for embedded images)

**Security Note**: `'unsafe-inline'` is permitted for scripts and styles due to framework requirements (Tailwind CSS, inline event handlers). In a future hardening phase, consider:
- Moving inline scripts to external files
- Using nonces or hashes for specific inline scripts
- Switching to Tailwind JIT mode with pre-compiled CSS

### Testing CSP Changes

When modifying CSP, test in browser console:
```javascript
// Should work:
fetch('/api/analytics/dashboard').then(r => r.json()).then(console.log)

// External CDN scripts should load without errors
```

---

## Prevention

To prevent similar issues:

1. **Test with browser DevTools open** - CSP violations appear in console
2. **Check Network tab** - Failed requests indicate CSP/CORS issues
3. **Use CSP report-only mode during development**:
   ```python
   response.headers["Content-Security-Policy-Report-Only"] = "..."  # Test without breaking
   ```
4. **Gradually tighten CSP** - Start permissive, tighten iteratively while testing

---

## Deployment

After deploying these fixes, the Docker container will automatically restart and apply changes:

```bash
# Verify fix is deployed
docker logs icebreaker-web 2>&1 | grep -i "error\|warning" | tail -20

# Test endpoints
curl http://localhost:9000/health
curl http://localhost:9000/api/analytics/dashboard
```

Dashboard and network maps should now work correctly!
