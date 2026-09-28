"""Resolve npm version ranges to concrete versions.

A manifest declares ranges; matching vulnerabilities needs exact versions. The registry
lists every version a package has published, and the range decides which of them
applies — the same job npm does when it writes a lockfile.

Only the ranges declared by the project itself are resolved here. Everything below them
is reached through the resolved dependency graphs of the versions chosen, so this is
the one place ranges appear at all.
"""

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from nodesemver import max_satisfying

from sbom_security.models import PackageRef, Requirement

NPM_REGISTRY = "https://registry.npmjs.org"

# The registry serves a much smaller document under this media type, carrying the
# version list without the changelogs and metadata that come with the full record.
ABBREVIATED = "application/vnd.npm.install-v1+json"

MAX_CONCURRENT_LOOKUPS = 10


class UnresolvableRequirement(Exception):
    """No published version of the package satisfies the range."""


@dataclass(frozen=True)
class NpmRegistry:
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

    async def published_versions(
        self, name: str, client: httpx.AsyncClient
    ) -> tuple[str, ...]:
        """Return every version the registry lists for a package."""
        response = await client.get(
            self.package_url(name), headers={"Accept": ABBREVIATED}
        )
        if response.status_code == 404:
            raise UnresolvableRequirement(f"{name} is not published on the registry")
        response.raise_for_status()

        versions = (response.json() or {}).get("versions") or {}
        return tuple(versions)

    async def resolve(
        self, requirements: list[Requirement]
    ) -> tuple[tuple[PackageRef, ...], tuple[str, ...]]:
        """Resolve requirements to exact versions.

        Returns what was resolved, and the requirements that could not be. A manifest
        can name things the registry cannot answer for — a local path, a git URL, an
        alias — and one of those should not prevent the rest from being reported on.
        """
        if not requirements:
            return (), ()

        limit = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            outcomes = await asyncio.gather(
                *(self._resolve_one(item, client, limit) for item in requirements)
            )

        resolved = tuple(ref for ref in outcomes if ref is not None)
        unresolved = tuple(
            f"{item.name}@{item.range}"
            for item, ref in zip(requirements, outcomes, strict=True)
            if ref is None
        )
        return resolved, unresolved

    async def _resolve_one(
        self,
        requirement: Requirement,
        client: httpx.AsyncClient,
        limit: asyncio.Semaphore,
    ) -> PackageRef | None:
        async with limit:
            try:
                versions = await self.published_versions(requirement.name, client)
            except (UnresolvableRequirement, httpx.HTTPError):
                return None

        return _best_match(requirement, versions)


def _best_match(
    requirement: Requirement, versions: tuple[str, ...]
) -> PackageRef | None:
    """Return the highest published version satisfying a range.

    A range that is not semver at all — a local path, a git URL, an alias — makes the
    matcher raise rather than return nothing, so both are treated the same way: the
    requirement simply cannot be resolved from the registry.
    """
    if not versions:
        return None

    try:
        chosen: Any = max_satisfying(list(versions), requirement.range, loose=True)
    except Exception:  # pylint: disable=broad-exception-caught
        return None

    if not chosen:
        return None
    return PackageRef(name=requirement.name, version=str(chosen))
