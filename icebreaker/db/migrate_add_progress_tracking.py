"""
Database migration: Add progress tracking columns to scans and targets tables.

This migration adds the following columns:
- scans.phase: Current scan phase (ping_sweep, port_scan, analysis, writing, completed)
- scans.progress_percentage: Progress percentage (0-100)
- scans.alive_hosts: Number of hosts that responded to ping
- scans.current_target: Currently scanning target
- scans.ports_scanned: Total ports scanned so far
- targets.is_alive: Whether target responded to ping (Boolean, nullable)

Run this script to migrate an existing database.
"""
import sqlite3
import sys
from pathlib import Path


def migrate_database(db_path: str):
    """Apply migration to add progress tracking columns."""
    print(f"🔄 Migrating database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(scans)")
        scans_columns = {row[1] for row in cursor.fetchall()}

        cursor.execute("PRAGMA table_info(targets)")
        targets_columns = {row[1] for row in cursor.fetchall()}

        # Add columns to scans table
        scans_migrations = [
            ("phase", "ALTER TABLE scans ADD COLUMN phase VARCHAR(50) DEFAULT 'initializing'"),
            ("progress_percentage", "ALTER TABLE scans ADD COLUMN progress_percentage INTEGER DEFAULT 0"),
            ("alive_hosts", "ALTER TABLE scans ADD COLUMN alive_hosts INTEGER DEFAULT 0"),
            ("current_target", "ALTER TABLE scans ADD COLUMN current_target VARCHAR(255)"),
            ("ports_scanned", "ALTER TABLE scans ADD COLUMN ports_scanned INTEGER DEFAULT 0"),
        ]

        for column_name, sql in scans_migrations:
            if column_name not in scans_columns:
                print(f"  ✓ Adding scans.{column_name}")
                cursor.execute(sql)
            else:
                print(f"  ⊙ Column scans.{column_name} already exists")

        # Add column to targets table
        if "is_alive" not in targets_columns:
            print(f"  ✓ Adding targets.is_alive")
            cursor.execute("ALTER TABLE targets ADD COLUMN is_alive BOOLEAN")
        else:
            print(f"  ⊙ Column targets.is_alive already exists")

        conn.commit()
        print("✅ Migration completed successfully!")

    except Exception as e:
        conn.rollback()
        print(f"❌ Migration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    # Default database paths
    possible_paths = [
        "/data/icebreaker.db",  # Docker path
        "./icebreaker.db",      # Local path
        "./data/icebreaker.db", # Alternative local path
    ]

    # Use provided path or find existing database
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    else:
        db_path = None
        for path in possible_paths:
            if Path(path).exists():
                db_path = path
                break

        if not db_path:
            print("❌ No database found. Please specify path:")
            print(f"   python {sys.argv[0]} <path-to-database.db>")
            print("\nOr create a new database by starting the application.")
            sys.exit(1)

    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        sys.exit(1)

    migrate_database(db_path)
