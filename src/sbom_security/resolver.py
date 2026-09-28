"""Obtain SBOMs, and walk them to build a dependency tree.

Each package version's SBOM lists only what it depends on directly, so the tree is
built by expanding one level at a time: fetch the SBOMs of everything on the current
level, collect what they point at, and repeat. Depth is therefore a property of the
walk, not of anything stored, and every cached entry stays usable at any depth.

A walk starts either from a single package, or from the set a project declares. The
difference is only where the first level comes from.
"""

import asyncio
from collections.abc import Sequence

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef, Resolution, Sbom
from sbom_security.purl import to_purl
from sbom_security.registry import DepsDevClient, PackageNotFound

# A walk runs to the bottom of the tree unless a depth is asked for. It is bounded by
# a package count instead, so that it always terminates: depth cannot be predicted
# from the outside, but a ceiling on how much work one request may cause can be.
DEFAULT_DEPTH: int | None = None
MAX_PACKAGES = 5000

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
    depth: int | None = DEFAULT_DEPTH,
    ceiling: int = MAX_PACKAGES,
) -> Resolution:
    """Walk one package's dependencies breadth-first, to the bottom by default.

    Pass ``depth`` for a shallower look: one gives the root and its direct
    dependencies. Packages already seen are never expanded twice, which also means a
    dependency cycle terminates.
    """
    seen: dict[str, PackageRef] = {to_purl(root): root}
    unresolved: list[str] = []

    # A root the registry does not know is an error worth reporting: the caller asked
    # about a package that does not exist. Failures further down are tolerated
    # instead, since one unknown package should not abandon a whole tree.
    frontier = _newly_seen([await sbom_for(root, cache, client)], seen, ceiling)
    truncated = await _walk(
        frontier, seen, unresolved, cache, client, _levels_after_first(depth), ceiling
    )

    return Resolution(
        root=root,
        packages=tuple(seen.values()),
        depth=depth,
        truncated=truncated,
        unresolved=tuple(unresolved),
    )


async def resolve_declared(
    declared: Sequence[PackageRef],
    cache: SbomCache,
    client: DepsDevClient,
    depth: int | None = DEFAULT_DEPTH,
    ceiling: int = MAX_PACKAGES,
) -> Resolution:
    """Walk outwards from the dependencies a project declares.

    Used where a project has no lockfile: its manifest names the first level directly,
    so there is no single root to start from. A depth of one covers just the declared
    dependencies.
    """
    seen: dict[str, PackageRef] = {to_purl(ref): ref for ref in declared}
    unresolved: list[str] = []

    frontier = list(seen.values())
    truncated = await _walk(
        frontier, seen, unresolved, cache, client, _levels_after_first(depth), ceiling
    )

    return Resolution(
        root=None,
        packages=tuple(seen.values()),
        depth=depth,
        truncated=truncated,
        unresolved=tuple(unresolved),
    )


def _levels_after_first(depth: int | None) -> int | None:
    """Depth counts the first level, which the callers have already taken."""
    return None if depth is None else max(depth - 1, 0)


async def _walk(
    frontier: list[PackageRef],
    seen: dict[str, PackageRef],
    unresolved: list[str],
    cache: SbomCache,
    client: DepsDevClient,
    levels: int | None,
    ceiling: int,
) -> bool:
    """Expand the frontier until it runs out, or a limit stops it.

    Returns whether anything was left unexpanded, which is the only honest way to say
    that parts of the tree were never looked at.
    """
    limit = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
    remaining = levels

    while frontier and len(seen) < ceiling:
        if remaining is not None:
            if remaining <= 0:
                break
            remaining -= 1

        sboms = await asyncio.gather(
            *(_expand(ref, cache, client, limit, unresolved) for ref in frontier)
        )
        frontier = _newly_seen(sboms, seen, ceiling)

    return bool(frontier)


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
    sboms: list[Sbom], seen: dict[str, PackageRef], ceiling: int
) -> list[PackageRef]:
    """Collect the dependencies not encountered before, recording them as seen.

    Stops at the ceiling rather than taking a whole level and overshooting it, since
    one level of a wide tree can be thousands of packages on its own.
    """
    discovered: list[PackageRef] = []
    for sbom in sboms:
        for dependency in sbom.dependencies:
            if len(seen) >= ceiling:
                return discovered
            purl = to_purl(dependency)
            if purl not in seen:
                seen[purl] = dependency
                discovered.append(dependency)
    return discovered
