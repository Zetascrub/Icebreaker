"""
Scheduled scan service using APScheduler.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
import logging

from icebreaker.db.database import SessionLocal
from icebreaker.db.models import ScanSchedule, ScanProfile, Scan, ScanStatus

logger = logging.getLogger(__name__)


class SchedulerService:
    """Manages scheduled scans using APScheduler."""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
        logger.info("Scheduler service started")

    def load_schedules_from_db(self):
        """Load all enabled schedules from database and add them to scheduler."""
        db = SessionLocal()
        try:
            schedules = db.query(ScanSchedule).filter(ScanSchedule.enabled == True).all()
            for schedule in schedules:
                self.add_schedule(schedule)
            logger.info(f"Loaded {len(schedules)} schedules from database")
        finally:
            db.close()

    def add_schedule(self, schedule: ScanSchedule):
        """
        Add a schedule to APScheduler.

        Args:
            schedule: ScanSchedule model instance
        """
        job_id = f"scan_schedule_{schedule.id}"

        # Remove existing job if it exists
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        # Create trigger based on schedule type
        trigger = self._create_trigger(schedule.schedule_type, schedule.schedule_value)
        if not trigger:
            logger.error(f"Invalid trigger for schedule {schedule.id}: {schedule.schedule_type} - {schedule.schedule_value}")
            return

        # Add job to scheduler
        self.scheduler.add_job(
            func=self._execute_scheduled_scan,
            trigger=trigger,
            id=job_id,
            args=[schedule.id],
            name=f"Scan: {schedule.name}",
            replace_existing=True
        )

        logger.info(f"Added schedule {schedule.id} ({schedule.name}) to scheduler")

    def remove_schedule(self, schedule_id: int):
        """
        Remove a schedule from APScheduler.

        Args:
            schedule_id: Schedule ID to remove
        """
        job_id = f"scan_schedule_{schedule_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
            logger.info(f"Removed schedule {schedule_id} from scheduler")

    def _create_trigger(self, schedule_type: str, schedule_value: str):
        """
        Create APScheduler trigger from schedule configuration.

        Args:
            schedule_type: Type of schedule (cron, interval, once)
            schedule_value: Value for the schedule

        Returns:
            APScheduler trigger object or None if invalid
        """
        try:
            if schedule_type == "cron":
                # Parse cron expression
                # Format: "minute hour day month day_of_week"
                # Example: "0 9 * * *" = Every day at 9:00 AM
                parts = schedule_value.split()
                if len(parts) != 5:
                    logger.error(f"Invalid cron expression: {schedule_value}")
                    return None
                return CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )

            elif schedule_type == "interval":
                # Parse interval
                # Format: "value unit" where unit is seconds, minutes, hours, days, weeks
                # Example: "1 hours" = Every 1 hour
                parts = schedule_value.split()
                if len(parts) != 2:
                    logger.error(f"Invalid interval expression: {schedule_value}")
                    return None

                value = int(parts[0])
                unit = parts[1].lower()

                kwargs = {}
                if unit in ['second', 'seconds']:
                    kwargs['seconds'] = value
                elif unit in ['minute', 'minutes']:
                    kwargs['minutes'] = value
                elif unit in ['hour', 'hours']:
                    kwargs['hours'] = value
                elif unit in ['day', 'days']:
                    kwargs['days'] = value
                elif unit in ['week', 'weeks']:
                    kwargs['weeks'] = value
                else:
                    logger.error(f"Invalid interval unit: {unit}")
                    return None

                return IntervalTrigger(**kwargs)

            elif schedule_type == "once":
                # Parse datetime
                # Format: ISO 8601 datetime string
                # Example: "2025-01-15T14:30:00"
                run_date = datetime.fromisoformat(schedule_value)
                return DateTrigger(run_date=run_date)

            else:
                logger.error(f"Unknown schedule type: {schedule_type}")
                return None

        except Exception as e:
            logger.error(f"Error creating trigger: {e}")
            return None

    def _execute_scheduled_scan(self, schedule_id: int):
        """
        Execute a scheduled scan.

        Args:
            schedule_id: Schedule ID to execute
        """
        db = SessionLocal()
        try:
            # Get schedule
            schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
            if not schedule:
                logger.error(f"Schedule {schedule_id} not found")
                return

            if not schedule.enabled:
                logger.info(f"Schedule {schedule_id} is disabled, skipping")
                return

            logger.info(f"Executing scheduled scan: {schedule.name}")

            # Get scan profile if specified
            scan_config = dict(schedule.scan_config) if schedule.scan_config else {}
            if schedule.scan_profile_id:
                profile = db.query(ScanProfile).filter(ScanProfile.id == schedule.scan_profile_id).first()
                if profile:
                    # Merge profile config with schedule config (schedule config takes precedence)
                    merged_config = dict(profile.config)
                    merged_config.update(scan_config)
                    scan_config = merged_config

            # Create scan settings dictionary
            settings = {
                'ports': scan_config.get('ports', 'top-1000'),
                'timeout': scan_config.get('timeout', 5),
                'host_conc': scan_config.get('host_conc', 10),
                'svc_conc': scan_config.get('svc_conc', 100),
                'insecure': scan_config.get('insecure', False),
                'ai_provider': scan_config.get('ai_provider', None),
                'ai_model': scan_config.get('ai_model', None)
            }

            # Create new scan
            scan = Scan(
                run_id=f"scheduled-{schedule.name.lower().replace(' ', '-')}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                name=f"{schedule.name} (Scheduled)",
                status=ScanStatus.PENDING,
                preset=scan_config.get('preset', 'quick'),
                settings=settings,
                target_count=len(schedule.targets),
                started_at=datetime.utcnow()
            )
            db.add(scan)
            db.commit()

            # Update schedule last_run
            schedule.last_run = datetime.utcnow()

            # Calculate next run time
            job = self.scheduler.get_job(f"scan_schedule_{schedule_id}")
            if job and job.next_run_time:
                schedule.next_run = job.next_run_time.replace(tzinfo=None)

            db.commit()

            logger.info(f"Created scan {scan.id} from schedule {schedule_id}")

            # Import and start scan engine (avoid circular import)
            from icebreaker.engine.runner import ScanRunner
            runner = ScanRunner(scan.id, schedule.targets, db)
            # Run scan in background
            import threading
            scan_thread = threading.Thread(target=runner.run)
            scan_thread.daemon = True
            scan_thread.start()

        except Exception as e:
            logger.error(f"Error executing scheduled scan {schedule_id}: {e}", exc_info=True)
        finally:
            db.close()

    def get_schedule_info(self, schedule_id: int) -> Optional[Dict[str, Any]]:
        """
        Get information about a scheduled job.

        Args:
            schedule_id: Schedule ID

        Returns:
            Dictionary with job info or None if not found
        """
        job_id = f"scan_schedule_{schedule_id}"
        job = self.scheduler.get_job(job_id)

        if not job:
            return None

        return {
            "id": job.id,
            "name": job.name,
            "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger)
        }

    def shutdown(self):
        """Shutdown the scheduler."""
        self.scheduler.shutdown()
        logger.info("Scheduler service stopped")


# Global scheduler instance
_scheduler_instance: Optional[SchedulerService] = None


def get_scheduler() -> SchedulerService:
    """Get the global scheduler instance."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = SchedulerService()
        _scheduler_instance.load_schedules_from_db()
    return _scheduler_instance
