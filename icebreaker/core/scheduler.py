"""
Scan scheduler service.
"""
from __future__ import annotations
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from sqlalchemy.orm import Session


class ScanScheduler:
    """Scheduler for automated scans."""

    def __init__(self, database_url: str):
        """
        Initialize the scheduler.

        Args:
            database_url: Database URL for job persistence
        """
        jobstores = {
            'default': SQLAlchemyJobStore(url=database_url)
        }

        self.scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            timezone='UTC'
        )
        self.running = False

    def start(self):
        """Start the scheduler."""
        if not self.running:
            self.scheduler.start()
            self.running = True

    def shutdown(self):
        """Shutdown the scheduler."""
        if self.running:
            self.scheduler.shutdown()
            self.running = False

    def schedule_scan(
        self,
        schedule_id: int,
        targets: List[str],
        scan_config: Dict[str, Any],
        schedule_type: str,
        schedule_value: str,
        db_session: Session
    ) -> str:
        """
        Schedule a scan.

        Args:
            schedule_id: Schedule database ID
            targets: List of target IPs/hostnames
            scan_config: Scan configuration dict
            schedule_type: Type of schedule (cron, interval, once)
            schedule_value: Schedule value (cron expression, interval, or datetime)
            db_session: Database session

        Returns:
            Job ID
        """
        # Create trigger based on schedule type
        trigger = self._create_trigger(schedule_type, schedule_value)

        # Schedule the job
        job = self.scheduler.add_job(
            func=self._execute_scheduled_scan,
            trigger=trigger,
            args=[schedule_id, targets, scan_config],
            id=f"schedule_{schedule_id}",
            replace_existing=True,
            name=f"Scheduled Scan {schedule_id}"
        )

        return job.id

    def _create_trigger(self, schedule_type: str, schedule_value: str):
        """Create appropriate trigger based on schedule type."""
        if schedule_type == "cron":
            # Parse cron expression
            parts = schedule_value.split()
            if len(parts) == 5:
                minute, hour, day, month, day_of_week = parts
                return CronTrigger(
                    minute=minute,
                    hour=hour,
                    day=day,
                    month=month,
                    day_of_week=day_of_week
                )
        elif schedule_type == "interval":
            # Parse interval (e.g., "1h", "30m", "1d")
            value = int(schedule_value[:-1])
            unit = schedule_value[-1]

            if unit == 'h':
                return IntervalTrigger(hours=value)
            elif unit == 'm':
                return IntervalTrigger(minutes=value)
            elif unit == 'd':
                return IntervalTrigger(days=value)
            elif unit == 'w':
                return IntervalTrigger(weeks=value)
        elif schedule_type == "once":
            # Parse datetime
            run_date = datetime.fromisoformat(schedule_value)
            return DateTrigger(run_date=run_date)

        raise ValueError(f"Invalid schedule type or value: {schedule_type}, {schedule_value}")

    async def _execute_scheduled_scan(
        self,
        schedule_id: int,
        targets: List[str],
        scan_config: Dict[str, Any]
    ):
        """
        Execute a scheduled scan.

        Args:
            schedule_id: Schedule ID
            targets: List of targets to scan
            scan_config: Scan configuration
        """
        from icebreaker.api.routers.scans import execute_scan
        from icebreaker.db.database import SessionLocal
        from icebreaker.db.models import Scan, ScanStatus
        import uuid

        # Create a new scan in database
        db = SessionLocal()
        try:
            scan = Scan(
                run_id=f"scheduled_{schedule_id}_{uuid.uuid4().hex[:8]}",
                status=ScanStatus.PENDING,
                scan_profile_id=scan_config.get("profile_id")
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # Execute the scan
            await execute_scan(
                scan_id=scan.id,
                targets=targets,
                config=scan_config
            )

        except Exception as e:
            print(f"Error executing scheduled scan {schedule_id}: {e}")
        finally:
            db.close()

    def cancel_schedule(self, schedule_id: int) -> bool:
        """
        Cancel a scheduled scan.

        Args:
            schedule_id: Schedule ID

        Returns:
            True if cancelled successfully
        """
        job_id = f"schedule_{schedule_id}"
        try:
            self.scheduler.remove_job(job_id)
            return True
        except Exception:
            return False

    def get_scheduled_jobs(self) -> List[Dict[str, Any]]:
        """
        Get all scheduled jobs.

        Returns:
            List of job information
        """
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            })
        return jobs

    def pause_schedule(self, schedule_id: int) -> bool:
        """Pause a scheduled scan."""
        job_id = f"schedule_{schedule_id}"
        try:
            self.scheduler.pause_job(job_id)
            return True
        except Exception:
            return False

    def resume_schedule(self, schedule_id: int) -> bool:
        """Resume a paused scheduled scan."""
        job_id = f"schedule_{schedule_id}"
        try:
            self.scheduler.resume_job(job_id)
            return True
        except Exception:
            return False
