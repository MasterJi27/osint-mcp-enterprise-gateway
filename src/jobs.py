#!/usr/bin/env python3
"""
Async Job Queue for OSINT MCP Enterprise Gateway.
Provides background processing for long-running scans.
"""

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .cache import osint_cache


JOB_TIMEOUT_SECONDS = int(os.getenv("OSINT_JOB_TIMEOUT_SECONDS", "3600"))
JOBS_DIR = Path(os.getenv("OSINT_JOBS_DIR", "jobs"))
JOB_RETENTION_HOURS = int(os.getenv("OSINT_JOB_RETENTION_HOURS", "168"))


class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class Job:
    id: str
    tool_name: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = JobStatus.PENDING.value
    created_at: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    progress: int = 0
    max_progress: int = 100
    worker_id: Optional[str] = None
    parent_job_id: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.result and isinstance(self.result, dict) and "raw_output" in self.result:
            result_copy = dict(self.result)
            if len(str(result_copy.get("raw_output", ""))) > 10000:
                result_copy["raw_output"] = "[output truncated for storage]"
            data["result"] = result_copy
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Job":
        return cls(**data)

    def is_terminal(self) -> bool:
        return self.status in {
            JobStatus.COMPLETED.value,
            JobStatus.FAILED.value,
            JobStatus.CANCELLED.value,
            JobStatus.TIMEOUT.value,
        }

    def age_hours(self) -> float:
        try:
            created = datetime.fromisoformat(self.created_at)
            age = datetime.now(timezone.utc) - created
            return age.total_seconds() / 3600
        except (ValueError, TypeError):
            return 0.0


class JobQueue:
    def __init__(self, jobs_dir: Path = JOBS_DIR):
        self.jobs_dir = jobs_dir
        self._jobs: Dict[str, Job] = {}
        self._lock = asyncio.Lock()
        self._workers: Dict[str, asyncio.Task] = {}
        self._running = False

        if not self.jobs_dir.exists():
            self.jobs_dir.mkdir(parents=True, exist_ok=True)

        self._load_existing_jobs()
        self._cleanup_old_jobs()

    def _job_file_path(self, job_id: str) -> Path:
        return self.jobs_dir / f"{job_id}.json"

    def _load_existing_jobs(self) -> None:
        for f in self.jobs_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                job = Job.from_dict(data)
                if not job.is_terminal():
                    self._jobs[job.id] = job
                elif job.age_hours() > JOB_RETENTION_HOURS / 24:
                    f.unlink(missing_ok=True)
            except (json.JSONDecodeError, KeyError, TypeError, OSError):
                f.unlink(missing_ok=True)

    def _cleanup_old_jobs(self) -> int:
        count = 0
        for f in self.jobs_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                job = Job.from_dict(data)
                if job.age_hours() > JOB_RETENTION_HOURS / 24:
                    f.unlink(missing_ok=True)
                    count += 1
            except (json.JSONDecodeError, KeyError, TypeError, OSError):
                f.unlink(missing_ok=True)
                count += 1
        return count

    def _persist_job(self, job: Job) -> None:
        try:
            file_path = self._job_file_path(job.id)
            file_path.write_text(
                json.dumps(job.to_dict(), ensure_ascii=True),
                encoding="utf-8",
            )
        except OSError:
            pass

    async def create_job(
        self,
        tool_name: str,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        parent_job_id: Optional[str] = None,
    ) -> Job:
        async with self._lock:
            job = Job(
                id=str(uuid.uuid4()),
                tool_name=tool_name,
                target=target,
                parameters=parameters or {},
                parent_job_id=parent_job_id,
            )
            self._jobs[job.id] = job
            self._persist_job(job)
            return job

    async def get_job(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            if job_id in self._jobs:
                return self._jobs[job_id]

            file_path = self._job_file_path(job_id)
            if file_path.exists():
                try:
                    data = json.loads(file_path.read_text(encoding="utf-8"))
                    return Job.from_dict(data)
                except (json.JSONDecodeError, KeyError, TypeError, OSError):
                    return None
            return None

    async def update_job(
        self,
        job_id: str,
        status: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        progress: Optional[int] = None,
    ) -> Optional[Job]:
        async with self._lock:
            job = await self.get_job(job_id)
            if not job:
                return None

            if status:
                job.status = status
                if status == JobStatus.RUNNING.value and not job.started_at:
                    job.started_at = datetime.now(timezone.utc).isoformat()
                elif status in {
                    JobStatus.COMPLETED.value,
                    JobStatus.FAILED.value,
                    JobStatus.CANCELLED.value,
                    JobStatus.TIMEOUT.value,
                }:
                    job.completed_at = datetime.now(timezone.utc).isoformat()

            if result is not None:
                job.result = result
            if error is not None:
                job.error = error
            if progress is not None:
                job.progress = min(max(0, progress), job.max_progress)

            self._jobs[job.id] = job
            self._persist_job(job)
            return job

    async def cancel_job(self, job_id: str) -> bool:
        async with self._lock:
            job = await self.get_job(job_id)
            if not job:
                return False

            if job.status == JobStatus.RUNNING.value and job.id in self._workers:
                self._workers[job.id].cancel()
                del self._workers[job.id]

            await self.update_job(job_id, status=JobStatus.CANCELLED.value)
            return True

    async def list_jobs(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Job]:
        async with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.created_at,
                reverse=True,
            )

            if status:
                jobs = [j for j in jobs if j.status == status]

            return jobs[offset : offset + limit]

    async def run_job(
        self,
        job_id: str,
        handler: Callable[[Job], Any],
    ) -> Job:
        job = await self.get_job(job_id)
        if not job:
            raise ValueError(f"Job not found: {job_id}")

        await self.update_job(job_id, status=JobStatus.RUNNING.value)

        task = asyncio.create_task(self._execute_job(job_id, handler))
        self._workers[job_id] = task
        return job

    async def _execute_job(
        self,
        job_id: str,
        handler: Callable[[Job], Any],
    ) -> None:
        try:
            job = await self.get_job(job_id)
            if not job:
                return

            result = await asyncio.wait_for(
                asyncio.to_thread(handler, job),
                timeout=JOB_TIMEOUT_SECONDS,
            )
            await self.update_job(job_id, status=JobStatus.COMPLETED.value, result=result)

        except asyncio.TimeoutError:
            await self.update_job(
                job_id,
                status=JobStatus.TIMEOUT.value,
                error=f"Job exceeded {JOB_TIMEOUT_SECONDS} second timeout",
            )

        except asyncio.CancelledError:
            await self.update_job(job_id, status=JobStatus.CANCELLED.value)

        except Exception as e:
            await self.update_job(job_id, status=JobStatus.FAILED.value, error=str(e))

        finally:
            self._workers.pop(job_id, None)

    async def stats(self) -> Dict[str, Any]:
        async with self._lock:
            by_status: Dict[str, int] = {}
            for job in self._jobs.values():
                by_status[job.status] = by_status.get(job.status, 0) + 1

            return {
                "total_jobs": len(self._jobs),
                "active_workers": len(self._workers),
                "by_status": by_status,
                "jobs_dir": str(self.jobs_dir),
                "retention_hours": JOB_RETENTION_HOURS,
            }

    async def clear_completed(self) -> int:
        async with self._lock:
            count = 0
            to_remove = []

            for job_id, job in self._jobs.items():
                if job.is_terminal() and job.age_hours() > JOB_RETENTION_HOURS / 24:
                    to_remove.append(job_id)

            for job_id in to_remove:
                file_path = self._job_file_path(job_id)
                file_path.unlink(missing_ok=True)
                del self._jobs[job_id]
                count += 1

            return count


job_queue = JobQueue()
