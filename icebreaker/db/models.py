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

    # Scan configuration stored as JSON
    settings = Column(JSON, nullable=False)

    # Target count for progress tracking
    target_count = Column(Integer, default=0)
    services_found = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)

    # Relationships
    targets = relationship("Target", back_populates="scan", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, run_id={self.run_id}, status={self.status})>"


class Target(Base):
    """Target host/IP address for scanning."""
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    address = Column(String(255), nullable=False)
    labels = Column(JSON, default=dict)

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

    def __repr__(self):
        return f"<Service(id={self.id}, target={self.target}, port={self.port})>"


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

    # Relationship
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"


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
