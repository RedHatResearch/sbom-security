"""REST interface.

A repository is submitted as its lockfile, or named so that its lockfile can be
fetched. Nothing is cloned and no package manager is run, so no code from the
repository under examination is ever executed.

Reports can be produced immediately, or submitted as work to be picked up by a worker
and collected later. The second suits large trees, where resolving everything for the
first time takes longer than a caller wants to hold a connection open.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status

from sbom_security import __version__
from sbom_security.cache import SbomCache
from sbom_security.github import DEFAULT_REF, GitHubSource, LockfileNotFound
from sbom_security.jobs import NOT_FOUND, JobState
from sbom_security.lockfile import parse_package_lock_data
from sbom_security.models import PackageRef, Report
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies
from sbom_security.queue import ArqQueue, connect
from sbom_security.registry import DepsDevClient, PackageNotFound
from sbom_security.report import build_report
from sbom_security.resolver import DEFAULT_DEPTH, resolve_tree

# Large projects pin thousands of packages, and each distinct advisory costs another
# request to OSV. The default keeps an unattended call bounded; raise it deliberately.
DEFAULT_LIMIT = 500
MAX_LIMIT = 5000
MAX_DEPTH = 10

CACHE_DIRECTORY = Path(os.environ.get("SBOM_CACHE_DIR", ".cache"))

Limit = Annotated[
    int,
    Query(
        ge=1,
        le=MAX_LIMIT,
        description=(
            "Maximum dependencies to examine. "
            "A report that hits the limit is marked truncated."
        ),
    ),
]

Depth = Annotated[
    int,
    Query(
        ge=1,
        le=MAX_DEPTH,
        description=(
            "How many levels of dependencies to walk. One gives direct dependencies. "
            "A walk stopped by this limit is marked truncated."
        ),
    ),
]

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Hold one Redis connection pool for the lifetime of the process.

    The queue is optional: without Redis the immediate endpoints still work, and only
    the submitted-work ones report themselves unavailable.
    """
    try:
        application.state.redis = await connect()
    except Exception:  # pylint: disable=broad-exception-caught
        # Any failure to reach Redis means the same thing here: run without a queue.
        # Narrowing this would only couple the API to one client library's exceptions.
        application.state.redis = None
    yield
    if application.state.redis is not None:
        await application.state.redis.close()


app = FastAPI(
    title="sbom-security",
    version=__version__,
    description="Report dependencies and the known vulnerabilities affecting them.",
    lifespan=lifespan,
)


def get_osv_client() -> OsvClient:
    """Provide the vulnerability source, so tests can substitute their own."""
    return OsvClient()


def get_github_source() -> GitHubSource:
    """Provide the lockfile source, so tests can substitute their own."""
    return GitHubSource()


def get_registry_client() -> DepsDevClient:
    """Provide the dependency-graph source, so tests can substitute their own."""
    return DepsDevClient()


def get_cache() -> SbomCache:
    """Provide the SBOM cache, so tests can point it at a temporary directory."""
    return SbomCache(CACHE_DIRECTORY)


async def get_queue(request: Request) -> ArqQueue:
    """Provide the work queue, so tests can substitute their own.

    Connecting is retried here rather than only at startup. A service that came up
    before Redis was reachable would otherwise stay without a queue until it was
    restarted, which is a harsh punishment for a slow start.
    """
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        try:
            redis = await connect()
        except Exception as unreachable:  # pylint: disable=broad-exception-caught
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No queue is available. Reports can still be requested directly.",
            ) from unreachable
        request.app.state.redis = redis
    return ArqQueue(redis)


async def _report(
    target: str,
    lockfile: dict[str, Any],
    client: OsvClient,
    limit: int,
) -> Report:
    """Report on a parsed lockfile, examining at most ``limit`` dependencies."""
    refs = parse_package_lock_data(lockfile)
    truncated = len(refs) > limit
    return await build_report(
        target=target,
        dependencies=to_dependencies(refs[:limit]),
        client=client,
        truncated=truncated,
    )


@app.get("/health")
def health() -> dict[str, str]:
    """Report that the service is running."""
    return {"status": "ok"}


@app.post("/reports/npm-lockfile")
async def report_from_npm_lockfile(
    lockfile: dict[str, Any],
    client: Annotated[OsvClient, Depends(get_osv_client)],
    limit: Limit = DEFAULT_LIMIT,
) -> Report:
    """Report on the contents of a package-lock.json sent as the request body."""
    return await _report(
        target=lockfile.get("name") or "unnamed project",
        lockfile=lockfile,
        client=client,
        limit=limit,
    )


@app.post("/jobs/npm-package", status_code=status.HTTP_202_ACCEPTED)
async def submit_npm_package(
    name: str,
    version: str,
    queue: Annotated[ArqQueue, Depends(get_queue)],
    response: Response,
    depth: Depth = DEFAULT_DEPTH,
    callback_url: str | None = None,
) -> JobState:
    """Hand a package to a worker and return straight away.

    Submitting the same package, version and depth while that work is still outstanding
    returns the identifier already in hand rather than queueing it a second time.

    Give ``callback_url`` to be told when it is done; otherwise collect the result from
    the returned identifier.
    """
    identifier = await queue.submit(name, version, depth, callback_url)
    response.headers["Location"] = f"/jobs/{identifier}"
    return await queue.state(identifier)


@app.get("/jobs/{identifier:path}")
async def job(
    identifier: str,
    queue: Annotated[ArqQueue, Depends(get_queue)],
) -> JobState:
    """Report where submitted work has got to, and its result once it has finished.

    The identifier contains slashes, being built from a Package URL, so it is matched
    as a path rather than a single segment.
    """
    state = await queue.state(identifier)
    if state.status == NOT_FOUND:
        raise HTTPException(status_code=404, detail=f"No such job: {identifier}")
    return state


@app.get("/reports/github")
async def report_for_github_repository(
    owner: str,
    repo: str,
    client: Annotated[OsvClient, Depends(get_osv_client)],
    source: Annotated[GitHubSource, Depends(get_github_source)],
    ref: str = DEFAULT_REF,
    limit: Limit = DEFAULT_LIMIT,
) -> Report:
    """Report on a public GitHub repository by reading its committed lockfile.

    Only ``package-lock.json`` is fetched. The default ref resolves to the
    repository's default branch, whatever it happens to be called.
    """
    try:
        lockfile = await source.fetch_lockfile(owner, repo, ref)
    except LockfileNotFound as missing:
        raise HTTPException(status_code=404, detail=str(missing)) from missing

    return await _report(
        target=f"{owner}/{repo}@{ref}",
        lockfile=lockfile,
        client=client,
        limit=limit,
    )


@app.get("/reports/npm-package")
async def report_for_npm_package(
    name: str,
    version: str,
    client: Annotated[OsvClient, Depends(get_osv_client)],
    registry: Annotated[DepsDevClient, Depends(get_registry_client)],
    cache: Annotated[SbomCache, Depends(get_cache)],
    depth: Depth = DEFAULT_DEPTH,
) -> Report:
    """Report on an npm package and the dependencies it pulls in.

    Dependency versions come from resolved graphs rather than from a lockfile, so no
    lockfile is needed. Each version's dependencies are cached permanently, since a
    published version cannot change what it depends on.

    The name is a query parameter so that scoped packages such as ``@babel/core``
    survive without ambiguity in the path.
    """
    root = PackageRef(name=name, version=version)
    try:
        resolution = await resolve_tree(root, cache, registry, depth=depth)
    except PackageNotFound as missing:
        raise HTTPException(status_code=404, detail=str(missing)) from missing

    return await build_report(
        target=f"{name}@{version}",
        dependencies=to_dependencies(resolution.packages),
        client=client,
        truncated=resolution.truncated,
    )
