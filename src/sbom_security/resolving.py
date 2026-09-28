"""Shared machinery for resolving declared ranges against a package index.

npm and Python differ in how versions compare and in what a range may say, but not in
what has to happen: ask the index what exists, pick what the range allows, and record
whatever could not be answered. That shape lives here; each ecosystem supplies only
the two steps that are genuinely its own.
"""

import asyncio

import httpx

from sbom_security.models import PackageRef, Requirement

MAX_CONCURRENT_LOOKUPS = 10


class VersionResolver:
    """Resolves requirements by asking an index which versions exist.

    Subclasses provide ``released_versions`` and ``best_match``; everything else —
    concurrency, error handling, and reporting what failed — is the same either way.
    """

    timeout: float
    transport: httpx.AsyncBaseTransport | None

    async def released_versions(
        self, name: str, client: httpx.AsyncClient
    ) -> tuple[str, ...]:
        """Return every version the index lists for a package."""
        raise NotImplementedError

    def best_match(
        self, requirement: Requirement, versions: tuple[str, ...]
    ) -> PackageRef | None:
        """Return the version a requirement resolves to, or None if none does."""
        raise NotImplementedError

    def describe(self, requirement: Requirement) -> str:
        """Name a requirement in the form it was written, for reporting."""
        return f"{requirement.name}{requirement.range}"

    async def resolve(
        self, requirements: list[Requirement]
    ) -> tuple[tuple[PackageRef, ...], tuple[str, ...]]:
        """Resolve requirements to exact versions.

        Returns what was resolved, and the requirements that could not be. A project
        can name things an index cannot answer for — a local path, a git URL, a
        package that was never published — and one of those should not prevent the
        rest from being reported on.
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
            self.describe(item)
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
                versions = await self.released_versions(requirement.name, client)
            except httpx.HTTPError:
                return None

        if not versions:
            return None
        return self.best_match(requirement, versions)
