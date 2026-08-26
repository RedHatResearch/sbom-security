"""The work a worker performs, kept independent of whatever runs it.

Nothing here imports the task queue. The queue calls these functions; they do not know
about it, which keeps the choice of queue a detail at the edge of the system rather
than something threaded through the logic.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies, to_purl
from sbom_security.registry import DepsDevClient
from sbom_security.report import as_dict, build_report
from sbom_security.resolver import resolve_tree

CACHE_DIRECTORY = Path(os.environ.get("SBOM_CACHE_DIR", ".cache"))

QUEUED = "queued"
IN_PROGRESS = "in_progress"
COMPLETE = "complete"
NOT_FOUND = "not_found"
FAILED = "failed"


@dataclass(frozen=True)
class JobState:
    """Where a submitted piece of work has got to.

    A failure carries the reason with it. Reporting only that something went wrong
    leaves the caller with nowhere to go.
    """

    id: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True)
class Sources:
    """Where the work reads from, and how a finished report is delivered.

    Gathering these into one argument keeps them substitutable in tests without the
    work needing a queue, a network, or a cache directory of its own.
    """

    cache: SbomCache
    registry: DepsDevClient
    osv: OsvClient
    transport: httpx.AsyncBaseTransport | None = None

    @classmethod
    def default(cls) -> "Sources":
        return cls(
            cache=SbomCache(CACHE_DIRECTORY),
            registry=DepsDevClient(),
            osv=OsvClient(),
        )


def job_id(name: str, version: str, depth: int) -> str:
    """Return a stable identifier for one request.

    Two callers asking the same question get the same identifier, so the second is
    recognised as already queued rather than run again. The depth is part of it
    because a shallower walk answers a different question, even about the same package.
    """
    return f"{to_purl(PackageRef(name=name, version=version))}@depth={depth}"


async def report_on_package(
    name: str,
    version: str,
    depth: int,
    callback_url: str | None = None,
    sources: Sources | None = None,
) -> dict[str, Any]:
    """Resolve a package's dependencies and report the vulnerabilities affecting them.

    Walking the tree fills the SBOM cache along the way, so later work involving any
    of the same versions finds them already resolved.
    """
    sources = sources or Sources.default()

    resolution = await resolve_tree(
        PackageRef(name=name, version=version),
        cache=sources.cache,
        client=sources.registry,
        depth=depth,
    )
    report = await build_report(
        target=f"{name}@{version}",
        dependencies=to_dependencies(resolution.packages),
        client=sources.osv,
        truncated=resolution.truncated,
    )

    payload = as_dict(report)
    if callback_url:
        await _notify(callback_url, payload, sources.transport)
    return payload


async def _notify(
    callback_url: str,
    payload: dict[str, Any],
    transport: httpx.AsyncBaseTransport | None,
) -> None:
    """Post a finished report to the address the caller gave.

    A caller that cannot be reached must not discard work that has already been done,
    so a failed delivery is passed over and the result stays available to collect.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
            response = await client.post(callback_url, json=payload)
            response.raise_for_status()
    except httpx.HTTPError:
        pass
