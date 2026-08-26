"""Obtain SBOMs, reusing whatever has already been built."""

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef, Sbom
from sbom_security.purl import to_purl
from sbom_security.registry import DepsDevClient


async def sbom_for(
    ref: PackageRef, cache: SbomCache, client: DepsDevClient
) -> Sbom:
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
