"""
Database migration: Add projects table and project_id to scans table.

This migration adds:
- projects table with fields for client/engagement organization
- scans.project_id foreign key to link scans to projects

Run this script to migrate an existing database.
"""
import sqlite3
import sys
from pathlib import Path


def migrate_database(db_path: str):
    """Apply migration to add projects system."""
    print(f"🔄 Migrating database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check if projects table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='projects'")
        projects_exists = cursor.fetchone() is not None

        if not projects_exists:
            print("  ✓ Creating projects table")
            cursor.execute("""
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(255) NOT NULL,
                    client_name VARCHAR(255),
                    description TEXT,
                    engagement_type VARCHAR(100),
                    start_date DATETIME,
                    end_date DATETIME,
                    status VARCHAR(20) NOT NULL DEFAULT 'active',
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by VARCHAR(100),
                    scope JSON,
                    notes TEXT,
                    tags JSON,
                    total_scans INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    critical_findings INTEGER DEFAULT 0,
                    high_findings INTEGER DEFAULT 0
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX ix_projects_id ON projects (id)")
            cursor.execute("CREATE INDEX ix_projects_name ON projects (name)")
            cursor.execute("CREATE INDEX ix_projects_status ON projects (status)")
            print("  ✓ Created indexes on projects table")
        else:
            print("  ⊙ Table projects already exists")

        # Check if project_id column exists in scans table
        cursor.execute("PRAGMA table_info(scans)")
        scans_columns = {row[1] for row in cursor.fetchall()}

        if "project_id" not in scans_columns:
            print("  ✓ Adding scans.project_id")
            cursor.execute("ALTER TABLE scans ADD COLUMN project_id INTEGER")
            cursor.execute("CREATE INDEX ix_scans_project_id ON scans (project_id)")
            print("  ✓ Created index on scans.project_id")
        else:
            print("  ⊙ Column scans.project_id already exists")

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
