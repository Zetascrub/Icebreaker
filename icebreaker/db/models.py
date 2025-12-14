"""
Database models for Icebreaker web interface.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship
import enum

Base = declarative_base()


class ScanStatus(enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Scan run metadata and configuration."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    preset = Column(String(50), nullable=False)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    # Scan history tracking
    parent_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)

    # Scan configuration stored as JSON
    settings = Column(JSON, nullable=False)

    # Target count for progress tracking
    target_count = Column(Integer, default=0)
    services_found = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)

    # Progress tracking
    phase = Column(String(50), default="initializing")  # initializing, ping_sweep, port_scan, analysis, completed
    progress_percentage = Column(Integer, default=0)  # 0-100
    alive_hosts = Column(Integer, default=0)  # Hosts responding to ping
    current_target = Column(String(255), nullable=True)  # Currently scanning target
    ports_scanned = Column(Integer, default=0)  # Total ports scanned so far

    # Relationships
    targets = relationship("Target", back_populates="scan", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    # Scan history relationships
    parent_scan = relationship("Scan", remote_side=[id], foreign_keys=[parent_scan_id], backref="child_scans")

    def __repr__(self):
        return f"<Scan(id={self.id}, run_id={self.run_id}, status={self.status})>"


class Target(Base):
    """Target host/IP address for scanning."""
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    address = Column(String(255), nullable=False)
    labels = Column(JSON, default=dict)
    is_alive = Column(Boolean, default=None, nullable=True)  # True if responded to ping, False if not, None if not checked

    # Relationship
    scan = relationship("Scan", back_populates="targets")

    def __repr__(self):
        return f"<Target(id={self.id}, address={self.address})>"


class Service(Base):
    """Discovered service on a target."""
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    name = Column(String(100), nullable=True)
    meta = Column(JSON, default=dict)

    # Relationship
    scan = relationship("Scan", back_populates="services")
    screenshots = relationship("Screenshot", back_populates="service", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Service(id={self.id}, target={self.target}, port={self.port})>"


class Screenshot(Base):
    """Screenshot of web service."""
    __tablename__ = "screenshots"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Screenshot metadata
    url = Column(String(1000), nullable=False)
    screenshot_path = Column(String(500), nullable=False)  # Relative path to screenshot file
    page_title = Column(String(500), nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)

    # Capture details
    capture_status = Column(String(20), default="pending")  # pending, success, failed
    error_message = Column(Text, nullable=True)
    captured_at = Column(DateTime, nullable=True)

    # Technology detection
    technologies = Column(JSON, default=list)  # Detected web technologies
    headers = Column(JSON, default=dict)  # HTTP response headers

    # Relationship
    service = relationship("Service", back_populates="screenshots")
    scan = relationship("Scan")

    def __repr__(self):
        return f"<Screenshot(id={self.id}, url={self.url}, status={self.capture_status})>"


class Finding(Base):
    """Security finding from analysis."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(255), nullable=False)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    tags = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    confidence = Column(Float, default=1.0)
    risk_score = Column(Float, nullable=True, index=True)
    recommendation = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False, index=True)

    # Template linkage
    template_id = Column(Integer, ForeignKey("finding_templates.id"), nullable=True, index=True)

    # Workflow & tracking
    status = Column(String(20), default="new", index=True)  # new, confirmed, in_progress, fixed, false_positive, accepted_risk
    assigned_to = Column(String(255), nullable=True)  # Username or email
    notes = Column(Text, nullable=True)  # Internal notes for tracking
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("Scan", back_populates="findings")
    template = relationship("FindingTemplate", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"


class FindingTemplate(Base):
    """Finding template with standardized descriptions and remediation."""
    __tablename__ = "finding_templates"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(100), unique=True, nullable=False, index=True)  # e.g., "ICEBREAKER-001"
    title = Column(String(500), nullable=False)
    category = Column(String(100), nullable=True, index=True)  # e.g., "TLS/SSL", "HTTP Headers", "Authentication"

    # Detailed information
    description = Column(Text, nullable=False)  # What is this finding?
    impact = Column(Text, nullable=False)  # What could happen if exploited?
    remediation = Column(Text, nullable=False)  # How to fix it?

    # Risk assessment
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

    # Compliance & references
    cwe_id = Column(String(50), nullable=True)  # e.g., "CWE-326"
    owasp_2021 = Column(String(100), nullable=True)  # e.g., "A02:2021 – Cryptographic Failures"
    pci_dss = Column(String(100), nullable=True)  # e.g., "Requirement 4.1"
    nist_csf = Column(String(100), nullable=True)  # NIST Cybersecurity Framework mapping
    references = Column(JSON, default=list)  # List of URLs, RFCs, etc.

    # Metadata
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255), nullable=True)  # Username who created/imported template

    # Relationships
    findings = relationship("Finding", back_populates="template")

    def __repr__(self):
        return f"<FindingTemplate(id={self.id}, finding_id={self.finding_id}, title={self.title})>"


class ScanProfile(Base):
    """Saved scan configuration profile."""
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    config = Column(JSON, nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    schedules = relationship("ScanSchedule", back_populates="profile")

    def __repr__(self):
        return f"<ScanProfile(id={self.id}, name={self.name})>"


class ScanSchedule(Base):
    """Scheduled scan configuration."""
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Schedule configuration
    schedule_type = Column(String(20), nullable=False)  # cron, interval, once
    schedule_value = Column(String(255), nullable=False)  # cron expression, interval, or datetime

    # Scan configuration
    targets = Column(JSON, nullable=False)  # List of targets
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)
    scan_config = Column(JSON, default=dict)

    # Status
    enabled = Column(Boolean, default=True, index=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    profile = relationship("ScanProfile", back_populates="schedules")

    def __repr__(self):
        return f"<ScanSchedule(id={self.id}, name={self.name}, enabled={self.enabled})>"


class NotificationConfig(Base):
    """Notification configuration for scan results."""
    __tablename__ = "notification_configs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True, index=True)

    # Notification type: email, slack, discord, teams, webhook
    type = Column(String(50), nullable=False)

    # Configuration (webhook URLs, email settings, etc.)
    config = Column(JSON, nullable=False)

    # Filtering
    min_severity = Column(String(20), default="low")  # Minimum severity to notify
    only_on_findings = Column(Boolean, default=False)  # Only notify if findings exist

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<NotificationConfig(id={self.id}, name={self.name}, type={self.type})>"


class CVE(Base):
    """CVE (Common Vulnerabilities and Exposures) information."""
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)

    # CVE details
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_v3_vector = Column(String(255), nullable=True)
    cvss_v2_vector = Column(String(255), nullable=True)

    # Additional information
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    has_known_exploit = Column(Boolean, default=False, index=True)
    references = Column(JSON, default=list)

    # Cache metadata
    cached_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding_cves = relationship("FindingCVE", back_populates="cve")

    def __repr__(self):
        return f"<CVE(id={self.id}, cve_id={self.cve_id}, severity={self.severity})>"


class FindingCVE(Base):
    """Association between findings and CVEs."""
    __tablename__ = "finding_cves"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False, index=True)

    # Relationships
    finding = relationship("Finding")
    cve = relationship("CVE", back_populates="finding_cves")

    def __repr__(self):
        return f"<FindingCVE(finding_id={self.finding_id}, cve_id={self.cve_id})>"


class AnalyzerPlugin(Base):
    """Registered analyzer plugins."""
    __tablename__ = "analyzer_plugins"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    version = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)

    # Plugin metadata
    enabled = Column(Boolean, default=True, index=True)
    file_path = Column(String(500), nullable=True)

    # Timestamps
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AnalyzerPlugin(id={self.id}, name={self.name}, version={self.version})>"


class PortPreset(Base):
    """Custom port preset definitions."""
    __tablename__ = "port_presets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    ports = Column(String(2000), nullable=False)  # Comma-separated port list or ranges (e.g., "80,443,8000-8100")
    is_default = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<PortPreset(id={self.id}, name={self.name})>"


class AIServiceConfig(Base):
    """AI service configuration (API keys, endpoints)."""
    __tablename__ = "ai_service_configs"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), unique=True, nullable=False, index=True)  # ollama, claude, openai
    enabled = Column(Boolean, default=True)

    # Configuration
    api_key = Column(String(500), nullable=True)  # Encrypted in production
    base_url = Column(String(500), nullable=True)  # For Ollama or custom endpoints
    model = Column(String(100), nullable=True)  # Default model
    config = Column(JSON, default=dict)  # Additional provider-specific settings

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AIServiceConfig(id={self.id}, provider={self.provider})>"


class ScanDefaults(Base):
    """Default scan configuration settings."""
    __tablename__ = "scan_defaults"

    id = Column(Integer, primary_key=True, index=True)
    setting_name = Column(String(100), unique=True, nullable=False, index=True)
    setting_value = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ScanDefaults(setting_name={self.setting_name}, value={self.setting_value})>"


class SMTPConfig(Base):
    """SMTP configuration for email notifications."""
    __tablename__ = "smtp_config"

    id = Column(Integer, primary_key=True, index=True)
    server = Column(String(255), nullable=False)
    port = Column(Integer, default=587)
    username = Column(String(255), nullable=True)
    password = Column(String(500), nullable=True)  # Encrypted in production
    from_email = Column(String(255), nullable=False)
    use_tls = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SMTPConfig(server={self.server}, port={self.port})>"


class CVEConfig(Base):
    """CVE/NVD database configuration."""
    __tablename__ = "cve_config"

    id = Column(Integer, primary_key=True, index=True)
    nvd_api_key = Column(String(500), nullable=True)  # NVD API key for higher rate limits
    cache_duration_days = Column(Integer, default=7)
    auto_lookup = Column(Boolean, default=True)  # Automatically lookup CVEs during scans

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<CVEConfig(auto_lookup={self.auto_lookup})>"


class ScanRetentionPolicy(Base):
    """Scan data retention policy."""
    __tablename__ = "scan_retention_policy"

    id = Column(Integer, primary_key=True, index=True)
    retention_days = Column(Integer, default=90)  # Keep scans for 90 days by default
    auto_cleanup = Column(Boolean, default=False)  # Automatically delete old scans
    keep_critical_findings = Column(Boolean, default=True)  # Keep scans with critical findings

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ScanRetentionPolicy(retention_days={self.retention_days})>"

