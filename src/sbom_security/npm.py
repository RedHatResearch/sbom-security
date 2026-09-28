"""Resolve npm version ranges to published versions.

A manifest declares ranges; matching vulnerabilities needs exact versions. The registry
lists every version a package has published, and the range decides which of them
applies — the same job npm does when it writes a lockfile.

Only the ranges declared by the project itself are resolved here. Everything below them
is reached through the resolved dependency graphs of the versions chosen, so this is
the one place ranges appear at all.
"""

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from nodesemver import max_satisfying

from sbom_security.models import NPM, PackageRef, Requirement
from sbom_security.resolving import VersionResolver

NPM_REGISTRY = "https://registry.npmjs.org"

# The registry serves a much smaller document under this media type, carrying the
# version list without the changelogs and metadata that come with the full record.
ABBREVIATED = "application/vnd.npm.install-v1+json"


@dataclass(frozen=True)
class NpmRegistry(VersionResolver):
    """Reads published versions from the npm registry.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = NPM_REGISTRY
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def package_url(self, name: str) -> str:
        """Return the registry URL for a package.

        A scoped name is escaped whole, so ``@babel/core`` stays one path segment.
        """
        return f"{self.base_url}/{quote(name, safe='')}"

    async def released_versions(
        self, name: str, client: httpx.AsyncClient
    ) -> tuple[str, ...]:
        """Return every version the registry lists for a package."""
        response = await client.get(
            self.package_url(name), headers={"Accept": ABBREVIATED}
        )
        if response.status_code == 404:
            return ()
        response.raise_for_status()

        return tuple((response.json() or {}).get("versions") or {})

    def best_match(
        self, requirement: Requirement, versions: tuple[str, ...]
    ) -> PackageRef | None:
        """Return the highest published version satisfying a range.

        A range that is not semver at all — a local path, a git URL, an alias — makes
        the matcher raise rather than return nothing, so both are treated the same
        way: the requirement simply cannot be resolved from the registry.
        """
        try:
            chosen: Any = max_satisfying(list(versions), requirement.range, loose=True)
        except Exception:  # pylint: disable=broad-exception-caught
            return None

        if not chosen:
            return None
        return PackageRef(name=requirement.name, version=str(chosen), ecosystem=NPM)

    def describe(self, requirement: Requirement) -> str:
        """npm ranges are written apart from the name, so show them that way."""
        return f"{requirement.name}@{requirement.range}"
