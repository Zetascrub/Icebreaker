# Database Migration Guide

## Automatic Migration (Recommended)

The application now automatically applies database migrations when it starts. Simply restart your Docker container and the migration will run automatically:

```bash
sudo docker-compose down
sudo docker-compose up -d
```

You should see this message in the logs:
```
🔄 Applying migration: Adding progress tracking columns...
✅ Migration completed successfully!
```

## Manual Migration (If Needed)

If you need to manually migrate the database, you can run:

```bash
# Inside the Docker container
sudo docker-compose exec icebreaker-web python -m icebreaker.db.migrate_add_progress_tracking

# Or locally
python -m icebreaker.db.migrate_add_progress_tracking /path/to/icebreaker.db
```

## What's Being Added

This migration adds the following columns:

### `scans` table:
- `phase` - Current scan phase (ping_sweep, port_scan, analysis, writing, completed)
- `progress_percentage` - Progress percentage (0-100)
- `alive_hosts` - Number of hosts that responded to ping
- `current_target` - Currently scanning target
- `ports_scanned` - Total ports scanned so far

### `targets` table:
- `is_alive` - Whether target responded to ping (Boolean, nullable)

## Troubleshooting

If you encounter database errors after updating:

1. **Check logs**: `sudo docker-compose logs icebreaker-web`
2. **Restart container**: `sudo docker-compose restart icebreaker-web`
3. **Nuclear option** (deletes all scan history):
   ```bash
   sudo docker-compose down
   rm -rf data/icebreaker.db
   sudo docker-compose up -d
   ```

## Backup Your Database

Before migrating, you can backup your database:

```bash
# Backup
cp data/icebreaker.db data/icebreaker.db.backup

# Restore if needed
cp data/icebreaker.db.backup data/icebreaker.db
```
