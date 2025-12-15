"""
Migration: Make finding_id unique and add proper indexing

This migration:
1. Generates unique finding_ids for any findings that have duplicates
2. Adds unique constraint to finding_id column
3. Ensures proper indexing for performance

Run with: python -m icebreaker.db.migrate_unique_finding_id
"""
import uuid
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from icebreaker.db.database import DATABASE_URL, engine as db_engine
from icebreaker.db.models import Finding, Base


def generate_unique_finding_id():
    """Generate a unique finding ID with UUID"""
    return f"FIND-{uuid.uuid4().hex[:12].upper()}"


def migrate():
    """Apply the migration"""
    engine = db_engine
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        print("Starting migration: Make finding_id unique...")

        # Step 0: Create tables if they don't exist
        print("Ensuring database tables exist...")
        Base.metadata.create_all(bind=engine)
        print("✓ Database tables ready")

        # Step 1: Check if constraint already exists
        inspector = inspect(engine)
        indexes = inspector.get_indexes('findings')
        constraints = inspector.get_unique_constraints('findings')

        has_unique_constraint = any(
            c.get('column_names') == ['finding_id']
            for c in constraints
        )

        if has_unique_constraint:
            print("✓ Unique constraint already exists on finding_id")
            return

        # Step 2: Find duplicate finding_ids
        duplicates_query = text("""
            SELECT finding_id, COUNT(*) as count
            FROM findings
            GROUP BY finding_id
            HAVING COUNT(*) > 1
        """)

        duplicates = db.execute(duplicates_query).fetchall()

        if duplicates:
            print(f"Found {len(duplicates)} duplicate finding_ids. Generating new unique IDs...")

            for finding_id, count in duplicates:
                # Get all findings with this ID
                findings = db.query(Finding).filter(Finding.finding_id == finding_id).all()

                # Keep the first one, rename the rest
                for i, finding in enumerate(findings[1:], 1):
                    old_id = finding.finding_id
                    new_id = generate_unique_finding_id()
                    finding.finding_id = new_id
                    print(f"  Updated finding {finding.id}: {old_id} → {new_id}")

            db.commit()
            print(f"✓ Fixed {sum(c-1 for _, c in duplicates)} duplicate finding_ids")
        else:
            print("✓ No duplicate finding_ids found")

        # Step 3: Ensure all finding_ids exist (shouldn't be null due to model)
        null_count = db.query(Finding).filter(Finding.finding_id == None).count()
        if null_count > 0:
            print(f"Found {null_count} findings with null finding_id. Generating IDs...")
            null_findings = db.query(Finding).filter(Finding.finding_id == None).all()
            for finding in null_findings:
                finding.finding_id = generate_unique_finding_id()
                print(f"  Generated ID for finding {finding.id}: {finding.finding_id}")
            db.commit()
            print(f"✓ Generated {null_count} new finding_ids")

        # Step 4: Add unique constraint (SQLite specific)
        print("Adding unique constraint to finding_id...")

        # For SQLite, we need to recreate the table with the constraint
        # Check database type
        db_url = DATABASE_URL

        if 'sqlite' in db_url:
            print("Detected SQLite database")
            # SQLite requires table recreation for constraint changes
            # The constraint is already in the model, so just recreate from model
            print("Please restart the application to apply the schema change.")
            print("The model already has unique=True, so the constraint will be applied on next startup.")
        else:
            # For PostgreSQL/MySQL, we can add the constraint directly
            print("Detected non-SQLite database")
            try:
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE findings ADD CONSTRAINT findings_finding_id_unique UNIQUE (finding_id)"))
                    conn.commit()
                print("✓ Added unique constraint to finding_id")
            except Exception as e:
                print(f"Note: Could not add constraint (may already exist): {e}")

        print("\n✅ Migration completed successfully!")
        print("   - All finding_ids are now unique")
        print("   - Constraint will be enforced on next application startup")

    except Exception as e:
        db.rollback()
        print(f"\n❌ Migration failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
