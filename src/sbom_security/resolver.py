"""Obtain SBOMs, and walk them to build a dependency tree.

Each package version's SBOM lists only what it depends on directly, so the tree is
built by expanding one level at a time: fetch the SBOMs of everything on the current
level, collect what they point at, and repeat. Depth is therefore a property of the
walk, not of anything stored, and every cached entry stays usable at any depth.
"""

import asyncio

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef, Resolution, Sbom
from sbom_security.purl import to_purl
from sbom_security.registry import DepsDevClient, PackageNotFound

DEFAULT_DEPTH = 3

# Bounded so that a wide dependency tree does not open hundreds of simultaneous
# connections against a free public service.
MAX_CONCURRENT_LOOKUPS = 10


async def sbom_for(ref: PackageRef, cache: SbomCache, client: DepsDevClient) -> Sbom:
    """Return the SBOM for a package version, building it only if it is not cached.

    Nothing invalidates these entries, because the dependencies a published version
    declares cannot change after the fact.
    """
    purl = to_purl(ref)

    cached = cache.get(purl)
    if cached is not None:
        return cached

    sbom = await client.direct_dependencies(ref)
    cache.put(sbom)
    return sbom


async def resolve_tree(
    root: PackageRef,
    cache: SbomCache,
    client: DepsDevClient,
    depth: int = DEFAULT_DEPTH,
) -> Resolution:
    """Walk a package's dependencies breadth-first, up to ``depth`` levels.

    A depth of one gives the root and its direct dependencies. Packages already seen
    are never expanded twice, which also means a dependency cycle terminates.
    """
    limit = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
    seen: dict[str, PackageRef] = {to_purl(root): root}
    unresolved: list[str] = []

    # A root the registry does not know is an error worth reporting: the caller asked
    # about a package that does not exist. Failures further down are tolerated
    # instead, since one unknown package should not abandon a whole tree.
    frontier = _newly_seen([await sbom_for(root, cache, client)], seen)

    for _ in range(depth - 1):
        if not frontier:
            break
        sboms = await asyncio.gather(
            *(_expand(ref, cache, client, limit, unresolved) for ref in frontier)
        )
        frontier = _newly_seen(sboms, seen)

    return Resolution(
        root=root,
        packages=tuple(seen.values()),
        depth=depth,
        # Anything still waiting to be expanded means the limit stopped the walk
        # short, so parts of the tree were never examined.
        truncated=bool(frontier),
        unresolved=tuple(unresolved),
    )


async def _expand(
    ref: PackageRef,
    cache: SbomCache,
    client: DepsDevClient,
    limit: asyncio.Semaphore,
    unresolved: list[str],
) -> Sbom:
    """Return one package's SBOM, treating an unknown package as a leaf.

    A single package the registry has no record of should not abandon the whole walk,
    but it is recorded rather than passed over silently.
    """
    async with limit:
        try:
            return await sbom_for(ref, cache, client)
        except PackageNotFound:
            purl = to_purl(ref)
            unresolved.append(purl)
            return Sbom(purl=purl, dependencies=())


def _newly_seen(
    sboms: list[Sbom], seen: dict[str, PackageRef]
) -> list[PackageRef]:
    """Collect the dependencies not encountered before, recording them as seen."""
    discovered: list[PackageRef] = []
    for sbom in sboms:
        for dependency in sbom.dependencies:
            purl = to_purl(dependency)
            if purl not in seen:
                seen[purl] = dependency
                discovered.append(dependency)
    return discovered
