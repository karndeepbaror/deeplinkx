"""Background scan jobs with progress events (consumed by the SSE endpoint)."""
from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from ..errors import DeeplinkXError
from ..scan import run_scan


@dataclass
class Job:
    id: str
    filename: str
    profile: str
    state: str = "queued"  # queued | running | done | error
    events: list[dict] = field(default_factory=list)
    scan_id: Optional[int] = None
    error: Optional[str] = None
    created: float = field(default_factory=time.time)
    cond: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def push(self, ev: dict) -> None:
        with self.cond:
            self.events.append(ev)
            self.cond.notify_all()

    def to_dict(self) -> dict:
        return {"id": self.id, "filename": self.filename, "profile": self.profile, "state": self.state,
                "scan_id": self.scan_id, "error": self.error, "progress": self.events[-1] if self.events else None}


class JobManager:
    def __init__(self, store, max_workers: int = 2, keep: int = 100):
        self.store = store
        self.jobs: dict[str, Job] = {}
        self.sem = threading.Semaphore(max_workers)
        self.keep = keep
        self.lock = threading.Lock()

    def submit(self, path: str, filename: str, profile: str, extra: Optional[dict] = None) -> Job:
        job = Job(uuid.uuid4().hex[:12], filename, profile)
        with self.lock:
            self.jobs[job.id] = job
            for old in sorted(self.jobs.values(), key=lambda j: j.created)[:-self.keep]:
                if old.state in ("done", "error"):
                    self.jobs.pop(old.id, None)
        threading.Thread(target=self._run, args=(job, path, extra or {}), daemon=True).start()
        return job

    def _run(self, job: Job, path: str, extra: dict) -> None:
        with self.sem:
            job.state = "running"
            job.push({"stage": "start", "fraction": 0.0, "message": "started"})
            try:
                from ..config import load_profile

                profile = load_profile(job.profile)
                if extra.get("assetlinks"):
                    profile.verify_assetlinks = True
                rep = run_scan(path, profile, progress=lambda s, f, m: job.push(
                    {"stage": s, "fraction": round(float(f), 3), "message": m}), store=self.store)
                job.scan_id = rep.scan_id
                job.state = "done"
                job.push({"stage": "done", "fraction": 1.0, "message": f"{len(rep.findings)} findings"})
            except DeeplinkXError as exc:
                job.error = str(exc)
                job.state = "error"
                job.push({"stage": "error", "fraction": 1.0, "message": job.error})
            except Exception as exc:  # never let a worker die silently
                job.error = f"{type(exc).__name__}: {exc}"
                job.state = "error"
                job.push({"stage": "error", "fraction": 1.0, "message": job.error})
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
