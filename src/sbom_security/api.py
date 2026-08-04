"""REST interface.

A repository is submitted as its lockfile rather than as a location to clone: the
lockfile is the authority on what is installed, and sending it avoids giving the
service network access to arbitrary repositories.
"""

from typing import Annotated, Any

from fastapi import Depends, FastAPI

from sbom_security import __version__
from sbom_security.lockfile import parse_package_lock_data
from sbom_security.models import Report
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies
from sbom_security.report import build_report

app = FastAPI(
    title="sbom-security",
    version=__version__,
    description="Report dependencies and the known vulnerabilities affecting them.",
)


def get_osv_client() -> OsvClient:
    """Provide the vulnerability source, so tests can substitute their own."""
    return OsvClient()


@app.get("/health")
def health() -> dict[str, str]:
    """Report that the service is running."""
    return {"status": "ok"}


@app.post("/reports/npm-lockfile")
def report_from_npm_lockfile(
    lockfile: dict[str, Any],
    client: Annotated[OsvClient, Depends(get_osv_client)],
) -> Report:
    """Report on the contents of a package-lock.json sent as the request body."""
    dependencies = to_dependencies(parse_package_lock_data(lockfile))
    return build_report(
        target=lockfile.get("name") or "unnamed project",
        dependencies=dependencies,
        client=client,
    )
