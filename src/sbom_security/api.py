"""REST interface.

A repository is submitted as its lockfile, or named so that its dependency files can
be fetched. Nothing is cloned and no package manager is run, so no code from the
repository under examination is ever executed.

Reports can be produced immediately, or submitted as work to be picked up by a worker
and collected later. The second suits large trees, where resolving everything for the
first time takes longer than a caller wants to hold a connection open.
"""

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status

from sbom_security import __version__
from sbom_security.cache import ExpiringCache, SbomCache
from sbom_security.endoflife import EndOfLifeClient
from sbom_security.github import DEFAULT_REF, FileNotFound, GitHubSource, LockfileNotFound
from sbom_security.jobs import NOT_FOUND, JobState, QueueOverview
from sbom_security.lockfile import parse_package_lock_data
from sbom_security.manifest import parse_package_json
from sbom_security.models import (
    LOCKFILE,
    MANIFEST,
    NPM,
    PYPI,
    PackageRef,
    Report,
    Requirement,
    Target,
)
from sbom_security.npm import NpmRegistry
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies
from sbom_security.pypi import PyPiIndex
from sbom_security.queue import ArqQueue, connect
from sbom_security.registry import DepsDevClient, PackageNotFound
from sbom_security.report import build_report, report_for_package
from sbom_security.requirements import parse_requirements_txt
from sbom_security.resolver import DEFAULT_DEPTH, resolve_declared

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
    int | None,
    Query(
        ge=1,
        le=MAX_DEPTH,
        description=(
            "How many levels of dependencies to walk. Omit to walk the whole tree; "
            "one gives direct dependencies only. A walk stopped short is marked "
            "truncated."
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
    description=(
        "Report dependencies, the known vulnerabilities affecting them, and whether "
        "they are still supported."
    ),
    lifespan=lifespan,
)


def get_osv_client() -> OsvClient:
    """Provide the vulnerability source, so tests can substitute their own."""
    return OsvClient()


def get_github_source() -> GitHubSource:
    """Provide the repository file source, so tests can substitute their own."""
    return GitHubSource()


def get_registry_client() -> DepsDevClient:
    """Provide the dependency-graph source, so tests can substitute their own."""
    return DepsDevClient()


def get_npm_registry() -> NpmRegistry:
    """Provide the npm registry, so tests can substitute their own."""
    return NpmRegistry()


def get_pypi_index() -> PyPiIndex:
    """Provide the Python package index, so tests can substitute their own."""
    return PyPiIndex()


def get_cache() -> SbomCache:
    """Provide the SBOM cache, so tests can point it at a temporary directory."""
    return SbomCache(CACHE_DIRECTORY)


def get_support_source() -> EndOfLifeClient:
    """Provide the support-lifecycle source, so tests can substitute their own."""
    return EndOfLifeClient(cache=ExpiringCache(CACHE_DIRECTORY / "endoflife"))


@dataclass(frozen=True)
class Sources:
    """Everything a report is built from.

    Gathering these into one dependency keeps endpoint signatures readable while each
    part stays separately substitutable, since they are resolved individually.
    """

    osv: OsvClient
    github: GitHubSource
    registry: DepsDevClient
    npm: NpmRegistry
    pypi: PyPiIndex
    cache: SbomCache
    support: EndOfLifeClient


def get_sources(
    osv: Annotated[OsvClient, Depends(get_osv_client)],
    github: Annotated[GitHubSource, Depends(get_github_source)],
    registry: Annotated[DepsDevClient, Depends(get_registry_client)],
    npm: Annotated[NpmRegistry, Depends(get_npm_registry)],
    pypi: Annotated[PyPiIndex, Depends(get_pypi_index)],
    cache: Annotated[SbomCache, Depends(get_cache)],
    support: Annotated[EndOfLifeClient, Depends(get_support_source)],
) -> Sources:
    return Sources(
        osv=osv,
        github=github,
        registry=registry,
        npm=npm,
        pypi=pypi,
        cache=cache,
        support=support,
    )


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


async def _report_from_lockfile(
    name: str, lockfile: dict[str, Any], sources: Sources, limit: int
) -> Report:
    """Report on a lockfile, which already pins every version it names."""
    refs = parse_package_lock_data(lockfile)
    return await build_report(
        target=Target(name=name, ecosystem=NPM, source=LOCKFILE),
        dependencies=to_dependencies(refs[:limit]),
        client=sources.osv,
        support=sources.support,
        truncated=len(refs) > limit,
    )


async def _report_from_declared(
    target: Target,
    declared: tuple[PackageRef, ...],
    unresolvable: tuple[str, ...],
    sources: Sources,
    limit: int,
    depth: int,
) -> Report:
    """Report on the dependencies a project declares, once they have been resolved.

    A manifest says what was asked for, not what was installed, so ranges are resolved
    to released versions before anything can be matched. What could not be resolved is
    carried through rather than quietly dropped.
    """
    resolution = await resolve_declared(
        declared, cache=sources.cache, client=sources.registry, depth=depth
    )
    packages = resolution.packages[:limit]

    return await build_report(
        target=target,
        dependencies=to_dependencies(packages),
        client=sources.osv,
        support=sources.support,
        truncated=resolution.truncated or len(resolution.packages) > limit,
        unresolved=unresolvable + resolution.unresolved,
    )


async def _resolve_requested_version(
    name: str, version: str | None, sources: Sources
) -> PackageRef:
    """Turn what the caller asked for into one published version.

    An omitted version means the newest release. A range such as ``^4.0.0`` means the
    newest that does not cross a major boundary. An exact version resolves to itself,
    and asking for one that was never published fails here with a clear answer rather
    than further down with a confusing one.

    Resolving before anything else matters for submitted work: the identifier has to
    name a version, or two requests months apart would share one job and the second
    would collect the first one's answer.
    """
    requested = Requirement(name=name, range=version or "*", ecosystem=NPM)
    resolved, _ = await sources.npm.resolve([requested])

    if not resolved:
        raise HTTPException(
            status_code=404,
            detail=f"No published version of {name} matches {version or 'latest'}.",
        )
    return resolved[0]


async def _declared_by_repository(
    owner: str, repo: str, ref: str, sources: Sources
) -> tuple[str, tuple[PackageRef, ...], tuple[str, ...]] | None:
    """Resolve what a repository declares, from whichever manifest it has.

    Returns the ecosystem it belongs to alongside the result. npm is tried before
    Python only because a project carrying both is more usually a JavaScript one with
    tooling alongside. None means neither file is present.
    """
    try:
        manifest = await sources.github.fetch_manifest(owner, repo, ref)
    except FileNotFound:
        pass
    else:
        declared: list[Requirement] = list(parse_package_json(manifest))
        resolved, unresolvable = await sources.npm.resolve(declared)
        return NPM, resolved, unresolvable

    try:
        content = await sources.github.fetch_requirements(owner, repo, ref)
    except FileNotFound:
        return None

    understood, ignored = parse_requirements_txt(content)
    resolved, unresolvable = await sources.pypi.resolve(list(understood))
    return PYPI, resolved, unresolvable + ignored


@app.get("/health")
def health() -> dict[str, str]:
    """Report that the service is running."""
    return {"status": "ok"}


@app.get("/queue")
async def queue_overview(
    queue: Annotated[ArqQueue, Depends(get_queue)],
) -> QueueOverview:
    """Report how much work is waiting and what the workers are doing.

    Submitted work otherwise disappears into the queue until it is collected, and a
    decision to run more workers has nothing to go on.
    """
    return await queue.overview()


@app.post("/reports/npm-lockfile")
async def report_from_npm_lockfile(
    lockfile: dict[str, Any],
    sources: Annotated[Sources, Depends(get_sources)],
    limit: Limit = DEFAULT_LIMIT,
) -> Report:
    """Report on the contents of a package-lock.json sent as the request body."""
    return await _report_from_lockfile(
        name=lockfile.get("name") or "unnamed project",
        lockfile=lockfile,
        sources=sources,
        limit=limit,
    )


@app.post("/jobs/npm-package", status_code=status.HTTP_202_ACCEPTED)
async def submit_npm_package(
    name: str,
    queue: Annotated[ArqQueue, Depends(get_queue)],
    sources: Annotated[Sources, Depends(get_sources)],
    response: Response,
    version: str | None = None,
    depth: Depth = DEFAULT_DEPTH,
    callback_url: str | None = None,
) -> JobState:
    """Hand a package to a worker and return straight away.

    ``version`` may be exact, a range, or left out for the newest release. It is
    settled here rather than in the worker, so that the identifier names a version:
    otherwise two requests months apart would share one job, and the later one would
    collect an answer about a version that is no longer the newest.

    Submitting the same package, version and depth while that work is still outstanding
    returns the identifier already in hand rather than queueing it a second time.

    Give ``callback_url`` to be told when it is done; otherwise collect the result from
    the returned identifier.
    """
    ref = await _resolve_requested_version(name, version, sources)
    identifier = await queue.submit(ref.name, ref.version, depth, callback_url)
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
    sources: Annotated[Sources, Depends(get_sources)],
    ref: str = DEFAULT_REF,
    limit: Limit = DEFAULT_LIMIT,
    depth: Depth = DEFAULT_DEPTH,
) -> Report:
    """Report on a public GitHub repository.

    A lockfile is used where the repository commits one, since it records exactly what
    is installed. Where it does not — libraries usually gitignore it, and yarn and pnpm
    projects never produce one — the manifest is read instead and its declared ranges
    are resolved. Both npm and Python projects are recognised.

    Only dependency files are fetched; nothing is cloned or executed.
    """
    name = f"{owner}/{repo}@{ref}"

    try:
        lockfile = await sources.github.fetch_lockfile(owner, repo, ref)
    except LockfileNotFound:
        pass
    else:
        return await _report_from_lockfile(
            name=name, lockfile=lockfile, sources=sources, limit=limit
        )

    found = await _declared_by_repository(owner, repo, ref, sources)
    if found is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"{owner}/{repo} has no dependency file this understands at {ref}: "
                "looked for package-lock.json, package.json and requirements.txt."
            ),
        )

    ecosystem, declared, unresolvable = found
    return await _report_from_declared(
        target=Target(name=name, ecosystem=ecosystem, source=MANIFEST),
        declared=declared,
        unresolvable=unresolvable,
        sources=sources,
        limit=limit,
        depth=depth,
    )


@app.get("/reports/npm-package")
async def report_for_npm_package(
    name: str,
    sources: Annotated[Sources, Depends(get_sources)],
    version: str | None = None,
    depth: Depth = DEFAULT_DEPTH,
) -> Report:
    """Report on an npm package and the dependencies it pulls in.

    ``version`` may be exact, a range such as ``^4.0.0``, or left out entirely for the
    newest release. Whatever is asked for, the report names the version it settled on.

    Dependency versions come from resolved graphs rather than from a lockfile, so no
    lockfile is needed. Each version's dependencies are cached permanently, since a
    published version cannot change what it depends on.

    The name is a query parameter so that scoped packages such as ``@babel/core``
    survive without ambiguity in the path.
    """
    ref = await _resolve_requested_version(name, version, sources)
    try:
        return await report_for_package(
            ref.name,
            ref.version,
            cache=sources.cache,
            registry=sources.registry,
            osv=sources.osv,
            support=sources.support,
            depth=depth,
        )
    except PackageNotFound as missing:
        raise HTTPException(status_code=404, detail=str(missing)) from missing
