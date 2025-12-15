# CSRF Protection

## Overview

Icebreaker implements Cross-Site Request Forgery (CSRF) protection to prevent unauthorized state-changing operations. CSRF protection is enabled by default for all form submissions and non-safe HTTP methods (POST, PUT, DELETE, PATCH).

## How It Works

1. **Token Generation**: When a user visits a page (GET request), a CSRF token is generated and stored in a cookie
2. **Token Validation**: When submitting a form or making a state-changing request, the token must be included in:
   - **Form submissions**: As a hidden form field named `csrf_token`
   - **AJAX requests**: As a header `X-CSRF-Token`
3. **Token Verification**: The server validates that the cookie token matches the submitted token

## Configuration

### Secret Key

CSRF tokens are signed using a secret key. Set this via environment variable:

```bash
export CSRF_SECRET_KEY="your-secure-random-string-here"
```

**Generate a secure key**:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Note**: If not set, a random key is generated at startup. This works for single-instance deployments but will cause issues with multiple instances (use Redis-backed sessions for multi-instance).

### Exempt Paths

By default, the following paths are exempt from CSRF protection:

- `/api/*` - API endpoints (will use JWT authentication in the future)
- `/health` - Health check endpoint
- `/docs` - OpenAPI documentation
- `/openapi.json` - OpenAPI specification

To customize exempt paths, modify `icebreaker/api/app.py`:

```python
csrf_exempt_paths = [
    "/api/",
    "/health",
    "/custom/webhook/path",
]
app.add_middleware(CSRFMiddleware, secret_key=csrf_secret, exempt_paths=csrf_exempt_paths)
```

## Using CSRF Tokens

### In HTML Forms

Add a hidden input field with the CSRF token:

```html
<form method="POST" action="/api/scans">
    <!-- CSRF token -->
    <input type="hidden" name="csrf_token" value="{{ get_csrf_token(request) }}">

    <!-- Other form fields -->
    <input type="text" name="scan_name" required>
    <button type="submit">Create Scan</button>
</form>
```

### In AJAX Requests

Include the CSRF token as a header:

```javascript
// Get CSRF token from cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Make AJAX request with CSRF token
fetch('/api/scans', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('csrf_token')
    },
    body: JSON.stringify({
        name: 'My Scan',
        targets: ['example.com']
    })
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
```

### In JavaScript Fetch with FormData

```javascript
const formData = new FormData();
formData.append('scan_name', 'Infrastructure Scan');
formData.append('csrf_token', getCookie('csrf_token'));

fetch('/api/scans', {
    method: 'POST',
    body: formData
})
.then(response => response.json())
.then(data => console.log(data));
```

## Error Responses

### Missing CSRF Cookie

**Status Code**: `403 Forbidden`

**Response**:
```json
{
  "detail": "CSRF cookie not found. Refresh the page and try again."
}
```

**Solution**: Refresh the page to get a new CSRF cookie.

### Missing CSRF Token

**Status Code**: `403 Forbidden`

**Response**:
```json
{
  "detail": "CSRF token not found in request. Include X-CSRF-Token header or csrf_token form field."
}
```

**Solution**: Include the CSRF token in your request (see examples above).

### Invalid CSRF Token

**Status Code**: `403 Forbidden`

**Response**:
```json
{
  "detail": "Invalid or expired CSRF token. Refresh the page and try again."
}
```

**Solution**: The token may have expired (default: 1 hour). Refresh the page to get a new token.

## Security Considerations

### Token Expiration

CSRF tokens expire after **1 hour** by default. This can be configured in `icebreaker/api/csrf.py`:

```python
def validate_token(self, token: str, max_age: int = 3600) -> bool:
    # Change max_age to your desired value (in seconds)
    ...
```

### Cookie Security

CSRF cookies are set with the following security attributes:

- **HttpOnly**: Yes - Cannot be accessed via JavaScript (prevents XSS attacks)
- **SameSite**: Lax - Cookie sent only for same-site requests
- **Secure**: Auto - Set to `True` when using HTTPS

### Double Submit Cookie Pattern

Icebreaker uses the **Double Submit Cookie** pattern:

1. CSRF token is stored in a cookie (first submit)
2. Same token must be submitted in request body/header (second submit)
3. Server validates both match

This prevents attackers from forging requests even if they can execute JavaScript on the victim's browser.

## Testing

### Test CSRF Protection Manually

```bash
# 1. Get CSRF cookie
curl -v http://localhost:8000/ -c cookies.txt

# 2. Extract token from cookie
TOKEN=$(grep csrf_token cookies.txt | awk '{print $7}')

# 3. Make authenticated request
curl -X POST http://localhost:8000/some/endpoint \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $TOKEN" \
  -b cookies.txt \
  -d '{"data": "value"}'
```

### Test in Python

```python
import requests

session = requests.Session()

# Get CSRF token
response = session.get("http://localhost:8000/")
csrf_token = session.cookies.get("csrf_token")

# Make authenticated request
response = session.post(
    "http://localhost:8000/api/scans",
    headers={"X-CSRF-Token": csrf_token},
    json={"name": "Test Scan", "targets": ["example.com"]}
)
print(response.json())
```

## Disabling CSRF Protection

**⚠️ Not recommended for production**

To disable CSRF protection (e.g., for testing):

1. Comment out the CSRF middleware in `icebreaker/api/app.py`:

```python
# app.add_middleware(CSRFMiddleware, secret_key=csrf_secret, exempt_paths=csrf_exempt_paths)
```

2. Or set all paths as exempt:

```python
csrf_exempt_paths = ["/"]  # Exempt all paths
```

## Production Deployment

### Single Instance

Generate a strong secret key and set it via environment:

```bash
export CSRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
icebreaker-web
```

### Multi-Instance (Load Balanced)

For multiple instances behind a load balancer, ensure all instances use the **same CSRF secret key**:

```bash
# .env file
CSRF_SECRET_KEY=your-shared-secret-key-here
```

Or use Redis-backed sessions for token storage (future enhancement).

### Docker

Set the secret key in your Docker Compose file:

```yaml
version: '3.8'
services:
  icebreaker:
    image: icebreaker:latest
    environment:
      - CSRF_SECRET_KEY=${CSRF_SECRET_KEY}
    env_file:
      - .env
```

### Kubernetes

Store the secret key in a Kubernetes Secret:

```bash
kubectl create secret generic icebreaker-secrets \
  --from-literal=csrf-secret-key=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
```

Reference in deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: icebreaker
spec:
  template:
    spec:
      containers:
      - name: icebreaker
        env:
        - name: CSRF_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: icebreaker-secrets
              key: csrf-secret-key
```

## Troubleshooting

### CSRF Protection Not Working

1. **Check middleware order**: CSRF middleware should be added after CORS but before routes
2. **Verify secret key**: Ensure `CSRF_SECRET_KEY` is set and consistent across instances
3. **Check exempt paths**: Verify your endpoint isn't in the exempt paths list

### CSRF Token Always Invalid

1. **Check cookie domain**: Ensure cookies are set for the correct domain
2. **Check SameSite policy**: If using cross-site requests, adjust SameSite policy
3. **Check HTTPS**: Secure cookies require HTTPS in production

### CSRF Protection Blocking Legitimate Requests

1. **Add endpoint to exempt paths** if it's an API endpoint with other auth
2. **Increase token expiration** if users have long-running sessions
3. **Check request format**: Ensure token is in correct location (header vs form field)

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Double Submit Cookie Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie)
- [FastAPI Security Best Practices](https://fastapi.tiangolo.com/tutorial/security/)
