# Changelog

All notable changes to Icebreaker will be documented in this file.

## [Unreleased]

### Added
- **CLI Nmap Support** - Added `--nmap` flag to enable Nmap-based port scanning for 10-100x speedup
- **DNS Analyzer** - Enabled DNS reconnaissance (A, AAAA, MX, NS, TXT, PTR, SPF/DMARC, zone transfers)
- **API Discovery Analyzer** - Enabled API endpoint discovery (REST, GraphQL, Swagger/OpenAPI, admin panels)
- **WAF/CDN Detector** - Enabled WAF and CDN detection (14+ WAFs, 12+ CDNs)
- **Nessus Plugin Import** - Added CLI command `icebreaker import nessus` for importing Nessus NASL plugins
- **Import Documentation** - Added NESSUS_IMPORT.md and NESSUS_QUICKSTART.md guides
- **Sample NASL Plugins** - Created sample plugins for testing import functionality

### Changed
- **CLI Analyzers** - Increased from 5 to 8 active analyzers by enabling previously web-only analyzers
- **README** - Updated to reflect new DNS, API, and WAF/CDN detection capabilities
- **README** - Added Nmap usage examples and CLI options table

### Notes
- All new analyzers were already fully implemented but only accessible via web UI
- Nmap integration was complete but not wired to CLI
- This release makes powerful existing features accessible via command line

## [0.2.0] - 2024-XX-XX

### Features
- Production-ready vulnerability scanner with enterprise features
- Multiple export formats (SARIF, HTML, JSON Lines, Markdown, CSV)
- AI-powered analysis (Ollama, Claude, OpenAI)
- Web interface with real-time updates
- Screenshot capture with technology detection
- Scheduled scans (cron, interval, once)
- Multi-channel notifications (Email, Slack, Discord, Teams, Webhooks)
- CVE/NVD database integration
- Plugin system for custom analyzers
- Docker deployment support

### Analyzers
- HTTP Basic (HTTPS redirects, HSTS validation, server headers)
- Security Headers (CSP, X-Frame-Options, HSTS, etc.)
- TLS Analyzer (certificate validation, weak protocols)
- Info Disclosure (sensitive files, directory listings)
- SSH Banner (version detection, outdated warnings)

### Performance
- Async/await throughout
- Parallel analyzer execution
- Configurable concurrency limits
- Intelligent rate limiting
- Connection pooling

## [0.1.0] - Initial Release

### Features
- Basic port scanning
- HTTP/HTTPS banner grabbing
- SSL/TLS certificate analysis
- Security header checks
- SARIF export
- Markdown summaries
