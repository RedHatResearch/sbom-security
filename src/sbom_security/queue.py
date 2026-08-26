"""Submitting work to the queue, and asking how it is getting on.

This is the only module that knows the queue is arq. Everything it submits lives in
``jobs``, which has no idea it is being run by anything in particular, so replacing
the queue means rewriting this file and nothing else.
"""

import os
from dataclasses import dataclass

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from arq.jobs import Job, JobStatus

from sbom_security.jobs import COMPLETE, FAILED, IN_PROGRESS, NOT_FOUND, QUEUED, JobState, job_id

REDIS_DSN = os.environ.get("REDIS_DSN", "redis://localhost:6379")

TASK = "report_on_package"

_ARQ_STATUS = {
    JobStatus.deferred: QUEUED,
    JobStatus.queued: QUEUED,
    JobStatus.in_progress: IN_PROGRESS,
    JobStatus.complete: COMPLETE,
    JobStatus.not_found: NOT_FOUND,
}


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(REDIS_DSN)


async def connect() -> ArqRedis:
    return await create_pool(redis_settings())


@dataclass(frozen=True)
class ArqQueue:
    """Puts work on the queue and reports on it."""

    redis: ArqRedis

    async def submit(
        self, name: str, version: str, depth: int, callback_url: str | None = None
    ) -> str:
        """Queue a report, or return the identifier of one already queued.

        arq refuses a job whose identifier is already present, which is what keeps the
        same package and version from being worked on twice at once.
        """
        identifier = job_id(name, version, depth)
        await self.redis.enqueue_job(
            TASK, name, version, depth, callback_url, _job_id=identifier
        )
        return identifier

    async def state(self, identifier: str) -> JobState:
        """Report where a job has got to, with its result once there is one."""
        job = Job(identifier, self.redis)
        status = _ARQ_STATUS.get(await job.status(), NOT_FOUND)

        if status != COMPLETE:
            return JobState(id=identifier, status=status)

        try:
            result = await job.result(timeout=0)
        except Exception as failure:  # pylint: disable=broad-exception-caught
            # The work raised rather than returning a report. Say so plainly, and pass
            # on why, instead of presenting a missing result as a finished one.
            return JobState(
                id=identifier,
                status=FAILED,
                error=f"{type(failure).__name__}: {failure}",
            )

        return JobState(id=identifier, status=COMPLETE, result=result)
