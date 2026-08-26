"""Look up the direct dependencies of a package version.

A package declares its dependencies as version ranges: express asks for
``"accepts": "~1.3.8"``. Turning that into an exact version means resolving the range
against everything published, which is the work a lockfile has already done and which
this project deliberately does not reimplement.

deps.dev publishes resolved dependency graphs per version, so the resolution is read
rather than computed. Only the nodes marked DIRECT are used: indirect dependencies are
reached by looking those up in turn, which keeps every cached entry complete on its own.
"""

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from sbom_security.models import PackageRef, Sbom
from sbom_security.purl import NPM, to_purl

DEPS_DEV_API = "https://api.deps.dev"

# deps.dev marks each node in the graph by its relationship to the package asked about.
SELF = "SELF"
DIRECT = "DIRECT"


class PackageNotFound(Exception):
    """The registry has no record of this package at this version."""


@dataclass(frozen=True)
class DepsDevClient:
    """Reads resolved dependency graphs from deps.dev.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = DEPS_DEV_API
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def dependencies_url(self, ref: PackageRef) -> str:
        """Return the deps.dev URL for a version's dependency graph.

        The name is escaped whole, so that a scoped package such as ``@babel/core``
        stays a single path segment instead of becoming two.
        """
        name = quote(ref.name, safe="")
        version = quote(ref.version, safe="")
        return (
            f"{self.base_url}/v3alpha/systems/{NPM}/packages/{name}"
            f"/versions/{version}:dependencies"
        )

    async def direct_dependencies(self, ref: PackageRef) -> Sbom:
        """Return the direct dependencies of one package version, at exact versions."""
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            response = await client.get(self.dependencies_url(ref))

        if response.status_code == 404:
            raise PackageNotFound(f"{ref.name}@{ref.version} is not known to deps.dev")
        response.raise_for_status()

        return Sbom(
            purl=to_purl(ref),
            dependencies=_direct_nodes(response.json()),
        )


def _direct_nodes(graph: dict[str, Any]) -> tuple[PackageRef, ...]:
    """Pick the directly depended-on versions out of a resolved dependency graph.

    The graph also contains the package itself, marked SELF, and everything reachable
    below it, marked INDIRECT. Both are skipped: the indirect ones are found by
    resolving each direct dependency in turn.
    """
    direct: list[PackageRef] = []
    for node in graph.get("nodes") or []:
        if node.get("relation") != DIRECT:
            continue
        key = node.get("versionKey") or {}
        name, version = key.get("name"), key.get("version")
        if name and version:
            direct.append(PackageRef(name=name, version=version))
    return tuple(direct)
