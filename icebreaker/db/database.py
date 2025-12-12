"""
Database connection and session management.
"""
from __future__ import annotations
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

# Database URL from environment or default to SQLite
# Use /data directory for database in Docker, current dir otherwise
db_path = "/data/icebreaker.db" if os.path.exists("/data") else "./icebreaker.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{db_path}")

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI to get database session.

    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables."""
    from icebreaker.db.models import Base
    Base.metadata.create_all(bind=engine)

    # Run migrations if needed
    apply_migrations()

    # Seed finding templates
    try:
        from icebreaker.db.seed_finding_templates import seed_finding_templates
        seed_finding_templates()
    except Exception as e:
        print(f"⚠️  Warning: Could not seed finding templates: {e}")


def apply_migrations():
    """Apply database migrations if needed."""
    import sqlite3
    from pathlib import Path

    # Only run migrations for SQLite databases
    if not DATABASE_URL.startswith("sqlite"):
        return

    # Extract database path from URL
    db_path_from_url = DATABASE_URL.replace("sqlite:///", "")

    if not Path(db_path_from_url).exists():
        return  # Database doesn't exist yet, no migration needed

    try:
        conn = sqlite3.connect(db_path_from_url)
        cursor = conn.cursor()

        # Check if migrations are needed
        cursor.execute("PRAGMA table_info(scans)")
        scans_columns = {row[1] for row in cursor.fetchall()}

        cursor.execute("PRAGMA table_info(targets)")
        targets_columns = {row[1] for row in cursor.fetchall()}

        # Migration: Add progress tracking columns
        if "phase" not in scans_columns:
            print("🔄 Applying migration: Adding progress tracking columns...")

            # Add columns to scans table
            cursor.execute("ALTER TABLE scans ADD COLUMN phase VARCHAR(50) DEFAULT 'initializing'")
            cursor.execute("ALTER TABLE scans ADD COLUMN progress_percentage INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE scans ADD COLUMN alive_hosts INTEGER DEFAULT 0")
            cursor.execute("ALTER TABLE scans ADD COLUMN current_target VARCHAR(255)")
            cursor.execute("ALTER TABLE scans ADD COLUMN ports_scanned INTEGER DEFAULT 0")

            # Add column to targets table
            cursor.execute("ALTER TABLE targets ADD COLUMN is_alive BOOLEAN")

            conn.commit()
            print("✅ Progress tracking migration completed!")

        # Migration: Add finding workflow and template support
        cursor.execute("PRAGMA table_info(findings)")
        findings_columns = {row[1] for row in cursor.fetchall()}

        if "status" not in findings_columns:
            print("🔄 Applying migration: Adding finding workflow and template support...")

            # Add columns to findings table
            cursor.execute("ALTER TABLE findings ADD COLUMN template_id INTEGER")
            cursor.execute("ALTER TABLE findings ADD COLUMN status VARCHAR(20) DEFAULT 'new'")
            cursor.execute("ALTER TABLE findings ADD COLUMN assigned_to VARCHAR(255)")
            cursor.execute("ALTER TABLE findings ADD COLUMN notes TEXT")
            cursor.execute("ALTER TABLE findings ADD COLUMN first_seen DATETIME DEFAULT CURRENT_TIMESTAMP")
            cursor.execute("ALTER TABLE findings ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP")

            conn.commit()
            print("✅ Finding workflow migration completed!")

        conn.close()
    except Exception as e:
        print(f"⚠️  Migration warning: {e}")
        # Don't fail startup if migration fails

