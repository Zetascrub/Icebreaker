# Icebreaker (v0.2)

🧊 **Production-ready vulnerability scanner and security assessment tool**

First-strike recon scanner with enterprise-grade features, comprehensive analyzers, and multiple export formats.

## ✨ Features

### Security
- ✅ **SSL/TLS certificate verification** (configurable with `--insecure` flag)
- ✅ **Input validation** (prevents command injection attacks)
- ✅ **Rate limiting** (protects against IDS/IPS triggering)
- ✅ **Async operations** (no blocking I/O)
- ✅ **Resource leak prevention** (proper connection cleanup)

### Vulnerability Detection
- 🔍 **Security Headers** - CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy
- 🔐 **SSL/TLS Analysis** - Weak protocols, expired certificates, self-signed certs
- 📁 **Information Disclosure** - .git, .env, backups, config files, directory listings
- 🌐 **HTTP Security** - Missing HTTPS redirects, HSTS, server header exposure
- 🔑 **SSH Analysis** - Banner grabbing, version detection

### Performance
- ⚡ **Parallel analyzer execution** - 3-10x faster than sequential
- 🚀 **Concurrent scanning** - Configurable concurrency limits
- 📊 **Intelligent rate limiting** - Requests/second control
- 💾 **DNS caching** - Reduced lookup overhead

### Reporting
- 📄 **Multiple Export Formats**:
  - **SARIF** - GitHub Security, Azure DevOps, GitLab integration
  - **HTML** - Interactive report with filtering and charts
  - **JSON Lines** - Machine-readable findings
  - **Markdown** - Human-readable summary
  - **AI Executive Summary** - AI-powered analysis and recommendations
- 📈 **Risk Scoring** - CVSS-like prioritization (0-10 scale)
- 🎯 **Confidence Ratings** - False positive filtering
- 🏷️ **Finding Tags** - Easy categorization
- 🤖 **AI Analysis** - Automated executive summaries with Ollama, Claude, or OpenAI

## 🚀 Quickstart

### Installation

```bash
# Create virtual environment
python -m venv .venv && source .venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Or without dev dependencies
pip install -e .
```

### Basic Usage

```bash
# Create scope file (one host per line)
echo "example.com" > scope.txt
echo "192.168.1.1" >> scope.txt

# Run scan with default settings
icebreaker --targets scope.txt

# Scan with custom ports
icebreaker -t scope.txt --ports "80,443,8080,8000-8100"

# Scan top 100 ports
icebreaker -t scope.txt --ports top100

# Disable SSL verification (for self-signed certs)
icebreaker -t scope.txt --insecure
```

### Advanced Usage

```bash
# High concurrency for fast scanning
icebreaker -t scope.txt --host-conc 256 --svc-conc 512

# Custom output directory
icebreaker -t scope.txt --out-dir /path/to/output

# Quiet mode (minimal console output)
icebreaker -t scope.txt --quiet

# Custom timeout
icebreaker -t scope.txt --timeout 3.0
```

### AI-Powered Analysis

Icebreaker can generate AI-powered executive summaries of scan results using various AI providers:

```bash
# Using Ollama (local, free)
icebreaker -t scope.txt --ai ollama

# Using Ollama with specific model
icebreaker -t scope.txt --ai ollama --ai-model llama3.2

# Using remote Ollama instance
icebreaker -t scope.txt --ai ollama --ai-base-url http://192.168.1.100:11434

# Using Claude (API key required)
export ANTHROPIC_API_KEY="your-api-key"
icebreaker -t scope.txt --ai claude

# Using Claude with specific model
icebreaker -t scope.txt --ai anthropic --ai-model claude-3-5-sonnet-20241022

# Using OpenAI (API key required)
export OPENAI_API_KEY="your-api-key"
icebreaker -t scope.txt --ai openai --ai-model gpt-4o
```

**AI Executive Summary includes:**
- High-level overview of security posture
- Key findings and critical issues highlighted
- Risk assessment (Critical/High/Medium/Low)
- Prioritized, actionable recommendations
- Technical details for security teams

**Supported AI Providers:**
- **Ollama** - Free, local LLM inference (requires Ollama running locally)
- **Anthropic Claude** - Requires `ANTHROPIC_API_KEY` environment variable
- **OpenAI** - Requires `OPENAI_API_KEY` environment variable

The AI summary is saved as `ai_executive_summary.md` in the output directory.

## 📊 Output Formats

### Directory Structure

```
runs/
└── 20241211T123456Z-a1b2c3-quick/
    ├── run.json                    # Run metadata
    ├── findings.jsonl              # Machine-readable findings
    ├── summary.md                  # Markdown summary
    ├── results.sarif               # SARIF for GitHub Security
    ├── report.html                 # Interactive HTML report
    ├── ai_executive_summary.md     # AI-generated executive summary (if --ai enabled)
    └── targets/
        └── example.com/
            └── services/
                ├── 80-http/
                │   └── meta.json
                └── 443-https/
                    └── meta.json
```

### SARIF Integration

Import results into GitHub Security:

```bash
# Upload to GitHub
gh api repos/:owner/:repo/code-scanning/sarifs \
  -F sarif=@runs/.../results.sarif \
  -F ref=refs/heads/main \
  -F sha=$GITHUB_SHA
```

### HTML Report

Open `report.html` in your browser for:
- Executive summary with statistics
- Risk distribution charts
- Interactive filtering by severity
- Searchable findings table
- Detailed target information

## 🔧 Configuration

### CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--targets` | `-t` | *required* | Path to scope file (one host per line) |
| `--preset` | | `quick` | Scan preset name |
| `--out-dir` | | `runs/<id>-<preset>` | Output directory |
| `--host-conc` | | `128` | Concurrent hosts |
| `--svc-conc` | | `256` | Concurrent service checks |
| `--quiet` | `-q` | `false` | Reduce console output |
| `--timeout` | | `1.5` | Per-request timeout (seconds) |
| `--insecure` | `-k` | `false` | Disable SSL verification |
| `--ports` | `-p` | `22,80,443` | Ports to scan |
| `--ai` | | `none` | AI provider (ollama, anthropic/claude, openai) |
| `--ai-model` | | provider default | AI model to use |
| `--ai-base-url` | | `localhost:11434` | Base URL for AI provider (for remote endpoints) |

### Port Specification

```bash
# Single ports
--ports "80,443,8080"

# Port ranges
--ports "8000-8100"

# Mixed
--ports "22,80,443,8000-8100"

# Presets
--ports "top100"    # Top 100 common ports
--ports "top1000"   # Top 1000 common ports
```

## 🧪 Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=icebreaker

# Run specific test file
pytest tests/test_port_parser.py

# Run with verbose output
pytest -v
```

### Test Structure

```
tests/
├── test_engine_smoke.py      # Smoke tests
├── test_http_basic.py         # HTTP analyzer tests
├── test_models.py             # Data model tests
├── test_port_parser.py        # Port parsing tests
├── test_input_validation.py   # Security validation tests
├── test_risk_scoring.py       # Risk scoring tests
└── test_analyzers.py          # Analyzer tests
```

### Code Quality

```bash
# Format code with ruff
ruff format .

# Lint code
ruff check .

# Auto-fix issues
ruff check --fix .
```

## 📈 Risk Scoring

Findings are automatically scored using a CVSS-like system:

| Severity | Base Score | Example |
|----------|------------|---------|
| CRITICAL | 9.0 | Expired SSL certificate, SQLi vulnerability |
| HIGH | 7.0 | Self-signed cert, missing authentication |
| MEDIUM | 5.0 | Missing security headers, weak CSP |
| LOW | 3.0 | Server header exposure, missing Referrer-Policy |
| INFO | 1.0 | Banner disclosure, documentation |

**Risk Score Formula**: `Base Score × Confidence`

Example:
- HIGH severity (7.0) × 100% confidence (1.0) = **7.0 risk score**
- HIGH severity (7.0) × 50% confidence (0.5) = **3.5 risk score**

Findings are automatically prioritized by risk score in all outputs.

## 🛡️ Security Best Practices

### Production Use

1. **Always use SSL verification** (default):
   ```bash
   icebreaker -t scope.txt  # SSL verification ON
   ```

2. **Only disable for internal testing**:
   ```bash
   icebreaker -t scope.txt --insecure  # Warning displayed
   ```

3. **Rate limiting** for sensitive targets:
   - Use lower concurrency values
   - Increase timeouts to avoid false negatives

4. **Validate targets** - Tool automatically validates IPs and hostnames to prevent injection

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no findings |
| 1 | Fatal error occurred |
| 2 | Scan completed, findings present |

Use in CI/CD:

```bash
#!/bin/bash
icebreaker -t scope.txt --quiet
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "Security findings detected!"
  exit 1
fi
```

## 🔌 Architecture

### Plugin System

Icebreaker uses a clean plugin architecture:

```
Detectors → Services → Analyzers → Findings → Writers
```

- **Detectors**: Discover services (TCP probe, HTTP banner grab)
- **Analyzers**: Examine services for vulnerabilities
- **Writers**: Export findings in various formats

### Adding Custom Analyzers

```python
from icebreaker.core.models import RunContext, Service, Finding

class MyAnalyzer:
    id = "my_analyzer"
    consumes = ["service:http", "service:https"]

    async def run(self, ctx: RunContext, service: Service) -> list[Finding]:
        findings = []
        # Your analysis logic here
        return findings
```

Register in `cli.py`:

```python
from icebreaker.analyzers.my_analyzer import MyAnalyzer

analyzers = [HTTPBasic(), SecurityHeaders(), MyAnalyzer()]
```

## 📚 Documentation

- **Architecture**: See `core/registry.py` for plugin protocols
- **Models**: See `core/models.py` for data structures
- **Risk Scoring**: See `core/risk_scoring.py` for algorithms
- **Examples**: See `tests/` for usage examples

## 🤝 Contributing

Contributions welcome! Areas of interest:

- Additional analyzers (XSS detection, SQL injection, etc.)
- More export formats (PDF, CSV)
- Performance optimizations
- Documentation improvements

## 📝 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

Built with:
- [typer](https://typer.tiangolo.com/) - CLI framework
- [httpx](https://www.python-httpx.org/) - HTTP client
- [pydantic](https://pydantic-docs.helpmanual.io/) - Data validation
- [rich](https://rich.readthedocs.io/) - Terminal output

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before scanning systems you don't own.
