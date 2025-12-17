"""
Database migration: Remove finding templates system.

This migration:
- Adds description, impact, and references columns to findings table
- Removes template_id foreign key from findings table
- Removes finding_templates table entirely
- Removes finding_template router and related code

Run this script to migrate an existing database.
"""
import sqlite3
import sys
from pathlib import Path


def migrate_database(db_path: str):
    """Apply migration to remove templates system."""
    print(f"🔄 Migrating database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check current schema
        cursor.execute("PRAGMA table_info(findings)")
        findings_columns = {row[1] for row in cursor.fetchall()}

        # Add new columns to findings table if they don't exist
        if "description" not in findings_columns:
            print("  ✓ Adding findings.description column")
            cursor.execute("ALTER TABLE findings ADD COLUMN description TEXT")
        else:
            print("  ⊙ Column findings.description already exists")

        if "impact" not in findings_columns:
            print("  ✓ Adding findings.impact column")
            cursor.execute("ALTER TABLE findings ADD COLUMN impact TEXT")
        else:
            print("  ⊙ Column findings.impact already exists")

        if "references" not in findings_columns:
            print("  ✓ Adding findings.references column")
            cursor.execute("ALTER TABLE findings ADD COLUMN references JSON")
        else:
            print("  ⊙ Column findings.references already exists")

        # SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
        # But first, let's check if template_id exists
        if "template_id" in findings_columns:
            print("  ✓ Removing findings.template_id column (recreating table)")

            # Create new findings table without template_id
            cursor.execute("""
                CREATE TABLE findings_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    finding_id VARCHAR(255) UNIQUE NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    target VARCHAR(255) NOT NULL,
                    port INTEGER,
                    tags JSON,
                    details JSON,
                    confidence FLOAT DEFAULT 1.0,
                    risk_score FLOAT,
                    description TEXT,
                    impact TEXT,
                    recommendation TEXT,
                    references JSON,
                    false_positive BOOLEAN DEFAULT 0,
                    status VARCHAR(20) DEFAULT 'new',
                    assigned_to VARCHAR(255),
                    notes TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            # Copy data from old table to new table
            cursor.execute("""
                INSERT INTO findings_new (
                    id, scan_id, finding_id, title, severity, target, port,
                    tags, details, confidence, risk_score, description, impact,
                    recommendation, references, false_positive, status, assigned_to,
                    notes, first_seen, last_seen
                )
                SELECT
                    id, scan_id, finding_id, title, severity, target, port,
                    tags, details, confidence, risk_score,
                    NULL as description, NULL as impact, recommendation,
                    '[]' as references, false_positive, status, assigned_to,
                    notes, first_seen, last_seen
                FROM findings
            """)

            # Drop old table and rename new one
            cursor.execute("DROP TABLE findings")
            cursor.execute("ALTER TABLE findings_new RENAME TO findings")

            # Recreate indexes
            cursor.execute("CREATE INDEX ix_findings_id ON findings (id)")
            cursor.execute("CREATE INDEX ix_findings_scan_id ON findings (scan_id)")
            cursor.execute("CREATE INDEX ix_findings_finding_id ON findings (finding_id)")
            cursor.execute("CREATE INDEX ix_findings_severity ON findings (severity)")
            cursor.execute("CREATE INDEX ix_findings_target ON findings (target)")
            cursor.execute("CREATE INDEX ix_findings_risk_score ON findings (risk_score)")
            cursor.execute("CREATE INDEX ix_findings_false_positive ON findings (false_positive)")
            cursor.execute("CREATE INDEX ix_findings_status ON findings (status)")

            print("  ✓ Created indexes on findings table")
        else:
            print("  ⊙ Column findings.template_id doesn't exist (already removed)")

        # Drop finding_templates table if it exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='finding_templates'")
        if cursor.fetchone():
            print("  ✓ Dropping finding_templates table")
            cursor.execute("DROP TABLE finding_templates")
        else:
            print("  ⊙ Table finding_templates doesn't exist (already removed)")

        conn.commit()
        print("✅ Migration completed successfully!")
        print("\n📝 Next steps:")
        print("   1. Restart the application")
        print("   2. Verify findings display correctly")
        print("   3. Run new scans to test plugin-based findings")

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
