# Rate Limiting

## Overview

Icebreaker uses [slowapi](https://github.com/laurentS/slowapi) to implement rate limiting on API endpoints. This prevents abuse and ensures fair resource usage.

## Configuration

Rate limiting is configured using the `RATE_LIMIT` environment variable:

```bash
# Default: 100 requests per minute per IP
export RATE_LIMIT="100/minute"

# More restrictive: 60 requests per minute
export RATE_LIMIT="60/minute"

# Less restrictive: 1000 requests per hour
export RATE_LIMIT="1000/hour"
```

## Default Limits

By default, the following rate limits apply:

- **General API endpoints**: 100 requests/minute per IP
- **Health check endpoint**: No rate limit (for monitoring)
- **WebSocket connections**: No rate limit

## Rate Limit Headers

When rate limiting is active, the API returns the following headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640000000
```

## Rate Limit Exceeded Response

When a client exceeds the rate limit, they receive:

**Status Code**: `429 Too Many Requests`

**Response Body**:
```json
{
  "error": "Rate limit exceeded: 100 per 1 minute"
}
```

## Disabling Rate Limiting

To disable rate limiting (not recommended for production):

```bash
export DISABLE_RATE_LIMITING="true"
```

Or modify `icebreaker/api/app.py`:

```python
# Comment out or remove the rate limiter initialization
# limiter = Limiter(key_func=get_remote_address)
```

## Production Considerations

### 1. Behind a Reverse Proxy

If running behind a reverse proxy (Nginx, Apache, etc.), ensure the real client IP is forwarded:

**Nginx**:
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

**Configure slowapi** to trust proxy headers in `app.py`:

```python
from slowapi.util import get_ipaddr

limiter = Limiter(key_func=get_ipaddr)  # Uses X-Forwarded-For if present
```

### 2. Redis Backend (Distributed Systems)

For multi-instance deployments, use Redis as the rate limit storage backend:

**Install Redis dependency**:
```bash
pip install redis
```

**Update app.py**:
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{redis_client.connection_pool.connection_kwargs['host']}:{redis_client.connection_pool.connection_kwargs['port']}"
)
```

### 3. Per-Endpoint Rate Limits

You can customize rate limits for specific endpoints:

```python
from fastapi import Request
from slowapi import Limiter

@app.get("/api/scans")
@limiter.limit("60/minute")  # More restrictive
async def list_scans(request: Request):
    ...

@app.post("/api/scans")
@limiter.limit("20/minute")  # Even more restrictive for expensive operations
async def create_scan(request: Request):
    ...
```

### 4. API Key-Based Rate Limiting

For authenticated API access, rate limit by API key instead of IP:

```python
def get_api_key(request: Request):
    """Extract API key from request for rate limiting."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key
    return get_remote_address(request)  # Fallback to IP

limiter = Limiter(key_func=get_api_key)
```

## Monitoring Rate Limits

### Prometheus Metrics (Future)

```python
from prometheus_client import Counter

rate_limit_hits = Counter('rate_limit_hits_total', 'Total rate limit hits', ['endpoint'])

# Track when rate limits are hit
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    rate_limit_hits.labels(endpoint=request.url.path).inc()
    return JSONResponse(
        status_code=429,
        content={"error": str(exc)}
    )
```

### Logging

slowapi automatically logs rate limit violations at the WARNING level:

```
WARNING:slowapi.extension:Rate limit exceeded for IP 192.168.1.100
```

## Testing

Test rate limiting locally:

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Send 200 requests with 10 concurrent connections
ab -n 200 -c 10 http://localhost:8000/api/scans

# Check for 429 responses in the output
```

## Security Best Practices

1. **Always enable rate limiting in production** to prevent DoS attacks
2. **Use Redis backend** for distributed deployments
3. **Monitor rate limit violations** to detect potential attacks
4. **Whitelist known IPs** (monitoring systems, CI/CD) if needed
5. **Combine with authentication** for better access control
6. **Set conservative limits** and increase only if legitimate use is blocked

## Troubleshooting

### Rate Limits Not Working

1. Check slowapi is installed: `pip show slowapi`
2. Verify limiter is added to app state: `app.state.limiter`
3. Check logs for rate limit violations
4. Ensure you're not whitelisting all IPs by accident

### Too Aggressive Rate Limiting

1. Increase the limit: `RATE_LIMIT="200/minute"`
2. Use per-endpoint limits instead of global limits
3. Switch to API key-based rate limiting for authenticated users

### Rate Limits Applied Inconsistently

1. Check if using in-memory storage with multiple workers
2. Switch to Redis backend for consistent limits across workers
3. Verify proxy headers are correctly forwarded

## References

- [slowapi Documentation](https://slowapi.readthedocs.io/)
- [OWASP Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [RFC 6585 - Additional HTTP Status Codes (429)](https://tools.ietf.org/html/rfc6585)
