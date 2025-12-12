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

    def __repr__(self):
        return f"<ScanProfile(id={self.id}, name={self.name})>"
