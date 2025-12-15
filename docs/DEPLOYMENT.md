# Deployment Guide

This guide covers deploying Icebreaker in various environments from development to production.

## Table of Contents

- [Quick Start (Development)](#quick-start-development)
- [Docker Deployment](#docker-deployment)
- [Production Deployment](#production-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Environment Variables](#environment-variables)
- [Security Hardening](#security-hardening)
- [Monitoring & Logging](#monitoring--logging)
- [Backup & Recovery](#backup--recovery)

---

## Quick Start (Development)

### Prerequisites

- Python 3.11 or higher
- pip
- virtualenv (recommended)
- nmap (optional, for faster scanning)

### Installation

```bash
# Clone repository
git clone https://github.com/Zetascrub/Icebreaker
cd Icebreaker

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Initialize database
mkdir -p data
python -c "from icebreaker.db.database import engine; from icebreaker.db.models import Base; Base.metadata.create_all(bind=engine)"

# Run CLI
icebreaker --help

# Run web server
icebreaker-web
```

---

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f icebreaker

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

### Using Docker Directly

```bash
# Build image
docker build -t icebreaker:latest .

# Run web server
docker run -d \
  --name icebreaker \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/runs:/app/runs \
  icebreaker:latest

# Run CLI scan
docker run --rm \
  -v $(pwd)/scope.txt:/tmp/scope.txt \
  -v $(pwd)/runs:/app/runs \
  icebreaker:latest \
  icebreaker -t /tmp/scope.txt

# View logs
docker logs -f icebreaker

# Stop container
docker stop icebreaker
```

### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  icebreaker:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./runs:/app/runs
    environment:
      - ICEBREAKER_API_KEY=${ICEBREAKER_API_KEY}
      - NVD_API_KEY=${NVD_API_KEY}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    restart: unless-stopped

volumes:
  ollama_data:
```

---

## Production Deployment

### System Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 4 GB
- Disk: 20 GB SSD
- Network: 100 Mbps

**Recommended:**
- CPU: 4-8 cores
- RAM: 8-16 GB
- Disk: 50 GB SSD (RAID 1)
- Network: 1 Gbps

### Using Systemd (Linux)

```bash
# 1. Install as system service
sudo useradd -r -s /bin/false icebreaker
sudo cp icebreaker.service /etc/systemd/system/
sudo systemctl daemon-reload

# 2. Enable and start
sudo systemctl enable icebreaker
sudo systemctl start icebreaker

# 3. Check status
sudo systemctl status icebreaker

# 4. View logs
sudo journalctl -u icebreaker -f
```

**icebreaker.service:**
```ini
[Unit]
Description=Icebreaker Security Scanner
After=network.target

[Service]
Type=simple
User=icebreaker
Group=icebreaker
WorkingDirectory=/opt/icebreaker
Environment="PATH=/opt/icebreaker/.venv/bin"
ExecStart=/opt/icebreaker/.venv/bin/uvicorn icebreaker.api.app:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Using Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/icebreaker
upstream icebreaker {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name scanner.example.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name scanner.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/scanner.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scanner.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

    # Max upload size for Nessus plugins
    client_max_body_size 1G;

    # Rate limiting (adjust as needed)
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;

    location / {
        proxy_pass http://icebreaker;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Apply rate limiting
        limit_req zone=api_limit burst=20 nodelay;

        # WebSocket support
        proxy_read_timeout 86400;
    }

    # Static files
    location /static {
        alias /opt/icebreaker/icebreaker/web/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/icebreaker /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Using PostgreSQL (Production Database)

```bash
# 1. Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# 2. Create database and user
sudo -u postgres psql
CREATE DATABASE icebreaker;
CREATE USER icebreaker_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE icebreaker TO icebreaker_user;
\q

# 3. Update database connection
# In icebreaker/db/database.py, change:
DATABASE_URL = "postgresql://icebreaker_user:your_secure_password@localhost/icebreaker"
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.20+)
- kubectl configured
- Helm (optional)

### Deployment Files

**namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: icebreaker
```

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: icebreaker
  namespace: icebreaker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: icebreaker
  template:
    metadata:
      labels:
        app: icebreaker
    spec:
      containers:
      - name: icebreaker
        image: ghcr.io/zetascrub/icebreaker:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: icebreaker-secrets
              key: database-url
        - name: ICEBREAKER_API_KEY
          valueFrom:
            secretKeyRef:
              name: icebreaker-secrets
              key: api-key
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: runs
          mountPath: /app/runs
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: icebreaker-data-pvc
      - name: runs
        persistentVolumeClaim:
          claimName: icebreaker-runs-pvc
```

**service.yaml:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: icebreaker
  namespace: icebreaker
spec:
  selector:
    app: icebreaker
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

**ingress.yaml:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: icebreaker
  namespace: icebreaker
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "1g"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - scanner.example.com
    secretName: icebreaker-tls
  rules:
  - host: scanner.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: icebreaker
            port:
              number: 80
```

**pvc.yaml:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: icebreaker-data-pvc
  namespace: icebreaker
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: icebreaker-runs-pvc
  namespace: icebreaker
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
```

**secrets.yaml:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: icebreaker-secrets
  namespace: icebreaker
type: Opaque
stringData:
  database-url: "postgresql://user:pass@postgres:5432/icebreaker"
  api-key: "your-secure-api-key-here"
```

### Deploy to Kubernetes

```bash
# Apply all manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# Check status
kubectl get pods -n icebreaker
kubectl get svc -n icebreaker
kubectl get ingress -n icebreaker

# View logs
kubectl logs -f deployment/icebreaker -n icebreaker

# Scale replicas
kubectl scale deployment/icebreaker --replicas=5 -n icebreaker
```

---

## Environment Variables

### Core Settings

```bash
# API Configuration
export ICEBREAKER_API_KEY="your-secret-api-key"
export ICEBREAKER_HOST="0.0.0.0"
export ICEBREAKER_PORT="8000"

# Database
export DATABASE_URL="sqlite:///data/icebreaker.db"  # or PostgreSQL URL

# AI Services
export OLLAMA_HOST="http://localhost:11434"
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."

# CVE Lookup
export NVD_API_KEY="your-nvd-api-key"

# Email Notifications
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM_EMAIL="scanner@example.com"

# Security
export SECRET_KEY="your-secret-key-for-sessions"
export ALLOWED_HOSTS="scanner.example.com,localhost"
export CORS_ORIGINS="https://scanner.example.com"
```

### Production Environment File

```bash
# .env.production
ICEBREAKER_ENV=production
ICEBREAKER_API_KEY=your-production-api-key
DATABASE_URL=postgresql://user:pass@postgres:5432/icebreaker
SECRET_KEY=your-production-secret-key
ALLOWED_HOSTS=scanner.example.com
CORS_ORIGINS=https://scanner.example.com
LOG_LEVEL=INFO
```

Load with:
```bash
export $(cat .env.production | xargs)
```

---

## Security Hardening

### 1. Enable HTTPS Only

```python
# Force HTTPS redirect in production
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

if os.getenv("ICEBREAKER_ENV") == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
```

### 2. Set Secure Headers

Already configured in Nginx above, or add to FastAPI:

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["scanner.example.com", "*.example.com"]
)
```

### 3. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

### 4. Rate Limiting

```bash
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req zone=api burst=20 nodelay;
```

### 5. Database Security

```bash
# PostgreSQL hardening
# /etc/postgresql/14/main/pg_hba.conf
host    icebreaker    icebreaker_user    127.0.0.1/32    scram-sha-256

# Disable remote connections
listen_addresses = 'localhost'
```

---

## Monitoring & Logging

### Application Logs

```bash
# Systemd logs
sudo journalctl -u icebreaker -f

# Docker logs
docker logs -f icebreaker

# Kubernetes logs
kubectl logs -f deployment/icebreaker -n icebreaker
```

### Log Aggregation (ELK Stack)

```yaml
# docker-compose with logging
services:
  icebreaker:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=icebreaker"
```

### Prometheus Metrics (Future)

```python
# Add to requirements
# prometheus-fastapi-instrumentator

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
```

Access metrics at: `http://localhost:8000/metrics`

### Health Check Endpoint

```bash
# Check if service is healthy
curl http://localhost:8000/health

# Expected response
{"status": "ok", "version": "0.2.0"}
```

---

## Backup & Recovery

### Database Backup

**SQLite:**
```bash
# Backup
sqlite3 data/icebreaker.db ".backup data/icebreaker_backup.db"

# Restore
cp data/icebreaker_backup.db data/icebreaker.db
```

**PostgreSQL:**
```bash
# Backup
pg_dump -U icebreaker_user icebreaker > icebreaker_backup.sql

# Restore
psql -U icebreaker_user icebreaker < icebreaker_backup.sql
```

### Automated Backups

```bash
# /etc/cron.daily/icebreaker-backup
#!/bin/bash
BACKUP_DIR="/backups/icebreaker"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
sqlite3 /opt/icebreaker/data/icebreaker.db ".backup $BACKUP_DIR/db_$DATE.db"

# Backup runs directory
tar -czf $BACKUP_DIR/runs_$DATE.tar.gz /opt/icebreaker/runs

# Keep only last 7 days
find $BACKUP_DIR -mtime +7 -delete

chmod +x /etc/cron.daily/icebreaker-backup
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo systemctl status icebreaker
sudo journalctl -u icebreaker -n 50

# Common issues:
# - Port 8000 already in use
# - Database file permissions
# - Missing environment variables
```

### High Memory Usage

```bash
# Check memory
docker stats icebreaker

# Reduce concurrency in scans
icebreaker -t scope.txt --host-conc 32 --svc-conc 64
```

### Database Lock Errors

```bash
# SQLite doesn't support multiple writers
# Solution: Use PostgreSQL for multi-instance deployments
```

---

## Performance Tuning

### Database Optimization

```sql
-- Add indexes (if not already present)
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_services_target ON services(target);

-- Vacuum database periodically
VACUUM;
ANALYZE;
```

### Worker Configuration

```bash
# Systemd service with multiple workers
ExecStart=/opt/icebreaker/.venv/bin/uvicorn icebreaker.api.app:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker
```

### Connection Limits

```python
# Increase connection pool size for high traffic
DATABASE_URL = "postgresql://user:pass@host/db?pool_size=20&max_overflow=10"
```

---

## Scaling Strategies

### Horizontal Scaling (Future)

1. **Use PostgreSQL** (not SQLite)
2. **Add Redis** for session storage
3. **Deploy multiple instances** behind load balancer
4. **Use Celery** for background tasks
5. **Separate services** (scan workers, API servers)

### Vertical Scaling

- Increase CPU/RAM for single instance
- Use faster storage (NVMe SSD)
- Optimize database queries
- Enable Nmap for faster scanning

---

## Conclusion

This guide covers deployment from development to production-grade Kubernetes clusters. For most use cases, Docker Compose or Systemd deployments are sufficient. Large-scale deployments should use Kubernetes with PostgreSQL and proper monitoring.

For support, see:
- GitHub Issues: https://github.com/Zetascrub/Icebreaker/issues
- Documentation: https://github.com/Zetascrub/Icebreaker
