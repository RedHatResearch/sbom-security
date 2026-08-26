"""REST interface.

A repository is submitted as its lockfile, or named so that its lockfile can be
fetched. Nothing is cloned and no package manager is run, so no code from the
repository under examination is ever executed.
"""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query

from sbom_security import __version__
from sbom_security.github import DEFAULT_REF, GitHubSource, LockfileNotFound
from sbom_security.lockfile import parse_package_lock_data
from sbom_security.models import Dependency, PackageRef, Report
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies
from sbom_security.report import build_report

# Large projects pin thousands of packages, and each distinct advisory costs another
# request to OSV. The default keeps an unattended call bounded; raise it deliberately.
DEFAULT_LIMIT = 500
MAX_LIMIT = 5000

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

app = FastAPI(
    title="sbom-security",
    version=__version__,
    description="Report dependencies and the known vulnerabilities affecting them.",
)


def get_osv_client() -> OsvClient:
    """Provide the vulnerability source, so tests can substitute their own."""
    return OsvClient()


def get_github_source() -> GitHubSource:
    """Provide the lockfile source, so tests can substitute their own."""
    return GitHubSource()


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
) -> Report:
    """Report on a single npm package at an exact version.

    This covers the named package only. Its dependencies are not included, because
    resolving them from the registry means turning the version ranges a package
    declares into exact versions, which a lockfile has already done.

    The name is a query parameter so that scoped packages such as ``@babel/core``
    survive without ambiguity in the path.
    """
    dependencies: list[Dependency] = list(
        to_dependencies([PackageRef(name=name, version=version)])
    )
    return await build_report(
        target=f"{name}@{version}",
        dependencies=dependencies,
        client=client,
    )
