"""The worker process.

Run with:

    arq sbom_security.worker.WorkerSettings

Workers are interchangeable and hold nothing between jobs: results go to the shared
SBOM cache and to Redis, so any number of them can run against the same queue.
"""

from typing import Any

from sbom_security import jobs
from sbom_security.queue import redis_settings


async def report_on_package(
    _ctx: dict[str, Any],
    name: str,
    version: str,
    depth: int,
    callback_url: str | None = None,
) -> dict[str, Any]:
    """Adapt the queue's calling convention to the plain function that does the work.

    arq hands every task a context dictionary as its first argument. Absorbing it here
    keeps ``jobs`` free of any knowledge of the queue.
    """
    return await jobs.report_on_package(name, version, depth, callback_url)


class WorkerSettings:  # pylint: disable=too-few-public-methods
    """What arq needs to know to run a worker."""

    functions = [report_on_package]
    redis_settings = redis_settings()
