# Icebreaker Architecture

## Overview

Icebreaker is a modern, async-first vulnerability scanner built with Python 3.11+ using a plugin-based architecture. It consists of three main components: CLI scanner, Web API, and Database layer.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interfaces                       │
├──────────────────────┬──────────────────────────────────────┤
│   CLI (Typer/Rich)   │   Web UI (FastAPI + HTML/JS)       │
└──────────┬───────────┴────────────┬─────────────────────────┘
           │                        │
           ├────────────────────────┤
           │                        │
┌──────────▼────────────────────────▼─────────────────────────┐
│                    Core Engine (Orchestrator)                │
│  ┌────────────┬────────────┬────────────┬─────────────┐    │
│  │ Detectors  │ Analyzers  │  Writers   │  Services   │    │
│  └────────────┴────────────┴────────────┴─────────────┘    │
└──────────┬──────────────────────┬────────────────────────────┘
           │                      │
    ┌──────▼──────┐        ┌─────▼──────┐
    │  Database   │        │  External  │
    │  (SQLite/   │        │  Services  │
    │  Postgres)  │        │  (NVD, AI) │
    └─────────────┘        └────────────┘
```

## Core Components

### 1. CLI Interface (`icebreaker/cli.py`)

**Purpose:** Command-line interface for running scans

**Features:**
- Target parsing from files
- Port specification (ranges, top N, custom)
- Concurrency configuration
- Nmap integration toggle
- AI analysis options
- Import commands for external data

**Example:**
```bash
icebreaker -t scope.txt --nmap --ports top1000 --ai ollama
```

### 2. Web API (`icebreaker/api/`)

**Framework:** FastAPI with async/await
**Port:** 8000 (default)

**Routers:**
- `/api/scans` - Scan management
- `/api/findings` - Finding CRUD
- `/api/targets` - Target management
- `/api/settings` - Configuration
- `/api/schedules` - Scheduled scans
- `/api/import` - Import vulnerability data
- `/api/analytics` - Statistics and charts
- `/api/exports` - Export in various formats
- `/ws/scans/{id}` - WebSocket for real-time updates

**Key Features:**
- Real-time scan progress via WebSockets
- Background task processing
- Session-based database access
- Auto-generated OpenAPI docs at `/docs`

### 3. Engine (`icebreaker/engine/`)

**Orchestrator Pattern:**

```python
class Orchestrator:
    def __init__(self, ctx, detectors, analyzers, writers):
        self.ctx = ctx
        self.detectors = detectors
        self.analyzers = analyzers
        self.writers = writers

    async def discover(self, targets) -> List[Service]:
        # Phase 1: Port scanning

    async def analyse(self, services) -> List[Finding]:
        # Phase 2: Vulnerability analysis

    def write_outputs(self, services, findings):
        # Phase 3: Report generation
```

**Execution Flow:**
```
Targets → Detectors → Services → Analyzers → Findings → Writers → Reports
```

## Plugin System

### Protocol-Based Design

All plugins implement simple protocols:

```python
# Detector Protocol
class Detector:
    async def run(self, ctx: RunContext, targets: List[Target]) -> List[Service]:
        ...

# Analyzer Protocol
class Analyzer:
    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        ...

# Writer Protocol
class Writer:
    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]):
        ...
```

### Built-in Components

**Detectors:**
- `TCPProbe` - Pure Python TCP connect scanner
- `NmapProbe` - Nmap integration for speed
- `BannerGrab` - HTTP/HTTPS banner grabbing

**Analyzers:**
- `HTTPBasic` - HTTP security checks
- `SecurityHeaders` - CSP, HSTS, X-Frame-Options, etc.
- `TLSAnalyzer` - SSL/TLS certificate validation
- `InfoDisclosure` - Sensitive file exposure (.git, .env)
- `DNSAnalyzer` - DNS reconnaissance
- `APIDiscovery` - API endpoint enumeration
- `WAFCDNDetector` - WAF and CDN identification
- `SSHBanner` - SSH version detection

**Writers:**
- `JSONLWriter` - JSON Lines format
- `MarkdownWriter` - Human-readable summary
- `SARIFWriter` - GitHub Security integration
- `HTMLWriter` - Interactive HTML reports
- `CSVWriter` - Spreadsheet format
- `AISummaryWriter` - AI-powered executive summary

## Data Models

### Core Models (`icebreaker/core/models.py`)

```python
class RunContext(BaseModel):
    run_id: str
    preset: str
    out_dir: str
    started_at: datetime
    settings: Dict[str, Any]

class Target(BaseModel):
    address: str
    labels: Dict[str, str]

class Service(BaseModel):
    target: str
    port: int
    name: Optional[str]
    meta: Dict[str, Any]

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    target: str
    port: Optional[int]
    tags: List[str]
    details: Dict[str, Any]
    confidence: float
    risk_score: Optional[float]
    recommendation: Optional[str]
    template_id: Optional[int]
```

### Database Models (`icebreaker/db/models.py`)

**16 Tables:**

**Scan Data:**
- `Scan` - Scan runs with progress tracking
- `Target` - Target hosts
- `Service` - Discovered services
- `Finding` - Security findings with workflow
- `Screenshot` - Web service screenshots

**Configuration:**
- `FindingTemplate` - Standardized vulnerability descriptions
- `ScanProfile` - Saved scan configurations
- `ScanSchedule` - Scheduled scans (cron/interval)
- `NotificationConfig` - Alert settings
- `PortPreset` - Custom port lists

**Integrations:**
- `CVE` - Cached CVE data from NVD
- `FindingCVE` - Finding-CVE associations
- `AnalyzerPlugin` - Registered plugins
- `AIServiceConfig` - AI provider settings

**System:**
- `SMTPConfig`, `CVEConfig`, `ScanRetentionPolicy`, `ScanDefaults`

## Async Architecture

### Why Async?

1. **I/O Bound Operations:** Network scanning is primarily I/O bound
2. **Concurrency:** Scan thousands of targets simultaneously
3. **Responsiveness:** Web UI remains responsive during scans
4. **Resource Efficiency:** Single thread handles many connections

### Async Execution Model

```python
# Concurrent port scanning
async def scan_ports(targets, ports):
    tasks = [
        asyncio.create_task(check_port(target, port))
        for target in targets
        for port in ports
    ]
    return await asyncio.gather(*tasks)

# Parallel analyzer execution
async def analyze_service(service):
    tasks = [
        asyncio.create_task(analyzer.run(ctx, service))
        for analyzer in analyzers
    ]
    results = await asyncio.gather(*tasks)
    return [f for result in results for f in result]
```

### Concurrency Controls

- `host_conc` - Max concurrent hosts (default: 128)
- `svc_conc` - Max concurrent service checks (default: 256)
- Semaphores prevent resource exhaustion
- Timeout handling for stuck connections

## Security Design

### Input Validation

```python
# IP address validation (prevents command injection)
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Hostname validation
def validate_hostname(hostname: str) -> bool:
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, hostname))
```

### SQL Injection Prevention

- SQLAlchemy ORM (no raw SQL)
- Parameterized queries only
- Input validation on all user data

### Path Traversal Protection

```python
# Tar extraction security
for member in tar.getmembers():
    if member.name.startswith('/') or '..' in member.name:
        continue  # Skip malicious paths
    tar.extract(member, extract_dir)
```

### SSL/TLS Verification

- Enabled by default
- `--insecure` flag required to disable
- Warnings displayed when verification disabled

## Performance Optimizations

### 1. Connection Pooling

```python
# HTTP client with connection reuse
client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    timeout=httpx.Timeout(10.0)
)
```

### 2. DNS Caching

- Local DNS cache for repeated lookups
- Reduces DNS query overhead
- TTL-based expiration

### 3. Rate Limiting

```python
# Token bucket algorithm
async with rate_limiter:
    await make_request(target)
```

### 4. Batch Processing

```python
# Commit database changes in batches
for i, item in enumerate(items):
    db.add(item)
    if i % 100 == 0:
        db.commit()
```

### 5. Nmap Integration

- 10-100x faster than pure Python
- Fallback to TCPProbe if unavailable
- XML output parsing

## Extensibility Points

### 1. Custom Analyzers

```python
# plugins/my_analyzer.py
from icebreaker.core.models import Service, Finding

class MyAnalyzer:
    id = "my_analyzer"

    async def run(self, ctx, service):
        findings = []
        # Your analysis logic
        return findings
```

### 2. Custom Writers

```python
class MyWriter:
    def write(self, ctx, services, findings):
        # Export in your format
        with open(f"{ctx.out_dir}/custom.txt", "w") as f:
            f.write(str(findings))
```

### 3. Custom Detectors

```python
class MyDetector:
    async def run(self, ctx, targets):
        services = []
        # Your discovery logic
        return services
```

## Database Schema Design

### Key Design Decisions

1. **JSON Fields for Flexibility**
   - `Service.meta` - Service-specific metadata
   - `Finding.details` - Finding-specific data
   - Allows schema evolution without migrations

2. **Audit Trails**
   - `created_at` / `updated_at` on all tables
   - `Scan.parent_scan_id` for scan history

3. **Workflow Support**
   - `Finding.status` - new, confirmed, in_progress, fixed, etc.
   - `Finding.assigned_to` - Assignment tracking
   - `Finding.notes` - Internal notes

4. **Compliance Mapping**
   - `FindingTemplate.owasp_2021`
   - `FindingTemplate.pci_dss`
   - `FindingTemplate.nist_csf`
   - `FindingTemplate.cwe_id`

### Indexes

Strategic indexes on hot paths:
- `Scan.status`, `Scan.run_id`
- `Finding.severity`, `Finding.scan_id`
- `FindingTemplate.finding_id`, `FindingTemplate.enabled`

## AI Integration

### Supported Providers

```python
# Ollama (local)
writer = AISummaryWriter(ai_provider="ollama", ai_model="llama3.2")

# Anthropic Claude
writer = AISummaryWriter(ai_provider="claude", ai_model="claude-3-5-sonnet")

# OpenAI
writer = AISummaryWriter(ai_provider="openai", ai_model="gpt-4o")
```

### AI Analysis Pipeline

```
Findings → Filter by Severity → Format Context → LLM → Executive Summary
```

## Deployment Architecture

### Single-Instance Deployment

```yaml
# docker-compose.yml
services:
  icebreaker:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./runs:/app/runs
```

### Kubernetes Deployment (Future)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: icebreaker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: icebreaker
  template:
    spec:
      containers:
      - name: icebreaker
        image: icebreaker:latest
        ports:
        - containerPort: 8000
```

## Monitoring and Observability

### Logging

```python
import logging

logger = logging.getLogger(__name__)
logger.info("Scan started")
logger.error("Scan failed", exc_info=True)
```

### Metrics (Future)

```python
from prometheus_client import Counter, Histogram

scans_total = Counter('scans_total', 'Total scans')
scan_duration = Histogram('scan_duration_seconds', 'Scan duration')
```

## Future Architecture Enhancements

### 1. Distributed Scanning

```
Load Balancer → Web API (3x replicas)
                   ↓
              Celery Workers (N)
                   ↓
           PostgreSQL + Redis
```

### 2. Microservices (Optional)

- Scan Service
- Analysis Service
- Report Service
- Notification Service

### 3. Event-Driven Architecture

```
Scan Started → Queue → Scan Workers → Findings → Notification Workers
```

## Technology Stack

**Core:**
- Python 3.11+
- FastAPI
- SQLAlchemy
- Pydantic

**CLI:**
- Typer
- Rich (formatting)

**Scanning:**
- httpx (HTTP)
- dnspython (DNS)
- pyOpenSSL (TLS)
- nmap (optional)

**Web:**
- Jinja2 (templates)
- Tailwind CSS
- Vanilla JavaScript

**Storage:**
- SQLite (default)
- PostgreSQL (production)

**AI:**
- Ollama
- Anthropic API
- OpenAI API

## Conclusion

Icebreaker's architecture prioritizes:
- **Extensibility** via plugin system
- **Performance** via async/await
- **Maintainability** via clean separation
- **Security** via input validation and safe defaults
- **Scalability** (future) via distributed design

The modular design allows easy addition of new analyzers, detectors, and export formats without touching core code.
