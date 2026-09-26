import asyncio
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import load_dotenv

from connectivity import check_connectivity, load_keys

TERMINAL = {"completed", "failed"}
SECRET_NAMES = (
    "VULTR_API_KEY", "vultr_api_key", "VULTR_INFERENCE_API_KEY", "VULTR_INFERENCE_KEY",
    "vultr_inference_api_key", "OPENAI_API_KEY", "NETBIRD_SANDBOX_SETUP_KEY",
)


def control_token():
    env_file = Path(__file__).with_name(".env")
    if env_file.exists() and env_file.stat().st_mode & 0o077:
        return None
    load_dotenv(env_file)
    token = os.getenv("CERBERUS_CONTROL_TOKEN")
    if not token or len(token) < 32 or token in (os.getenv(name) for name in SECRET_NAMES):
        return None
    return token


@dataclass
class Job:
    id: str = field(default_factory=lambda: uuid4().hex)
    status: str = "queued"
    result: dict | None = None
    error: str | None = None
    events: list[dict] = field(default_factory=lambda: [{"sequence": 0, "step": "connectivity", "status": "queued"}])
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)

    async def publish(self, status):
        async with self.condition:
            self.status = status
            self.events.append({"sequence": len(self.events), "step": "connectivity", "status": status})
            self.condition.notify_all()

    async def stream(self):
        cursor = 0
        while True:
            async with self.condition:
                await self.condition.wait_for(lambda: len(self.events) > cursor or self.status in TERMINAL)
                batch = self.events[cursor:]
                cursor = len(self.events)
                finished = self.status in TERMINAL
            for event in batch:
                yield event
            if finished:
                return


class JobRegistry:
    def __init__(self, max_jobs=32):
        self.max_jobs = max_jobs
        self.jobs = {}
        self.tasks = set()

    def create(self):
        if len(self.jobs) >= self.max_jobs:
            completed = next((job_id for job_id, job in self.jobs.items() if job.status in TERMINAL), None)
            if completed is None:
                return None
            self.jobs.pop(completed)
        job = Job()
        self.jobs[job.id] = job
        task = asyncio.create_task(run_connectivity_job(job))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job


async def run_connectivity_job(job):
    await job.publish("running")
    try:
        api_key, inference_key = load_keys()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            models, region_count = await check_connectivity(client, api_key, inference_key)
        job.result = {"models": models, "region_count": region_count}
    except Exception:
        job.error = "Connectivity check failed"
        await job.publish("failed")
    else:
        await job.publish("completed")
