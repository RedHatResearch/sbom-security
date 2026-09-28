"""Resolve Python version specifiers to released versions.

The same job the npm registry does for JavaScript, with different rules. Python
versions follow PEP 440 rather than semver, so the comparison and the specifier syntax
both differ, and the packaging library implements them.

A requirement with no specifier at all means any version, which resolves to the latest
release — the same thing installing it would do today.
"""

from dataclasses import dataclass
from urllib.parse import quote

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sbom_security.models import PYPI, PackageRef, Requirement
from sbom_security.resolving import VersionResolver

PYPI_INDEX = "https://pypi.org"


@dataclass(frozen=True)
class PyPiIndex(VersionResolver):
    """Reads released versions from the Python Package Index.

    ``transport`` exists so tests can answer requests without network access.
    """

    base_url: str = PYPI_INDEX
    timeout: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None

    def package_url(self, name: str) -> str:
        return f"{self.base_url}/pypi/{quote(name, safe='')}/json"

    async def released_versions(
        self, name: str, client: httpx.AsyncClient
    ) -> tuple[str, ...]:
        """Return every version the index lists for a package."""
        response = await client.get(self.package_url(name))
        if response.status_code == 404:
            return ()
        response.raise_for_status()
        return tuple((response.json() or {}).get("releases") or {})

    def best_match(
        self, requirement: Requirement, versions: tuple[str, ...]
    ) -> PackageRef | None:
        """Return the highest release satisfying a specifier.

        Pre-releases are left out unless the specifier asks for them, which is how pip
        behaves: a project asking for ``>=2.0`` does not expect a release candidate.
        """
        try:
            specifier = SpecifierSet(requirement.range or "")
        except InvalidSpecifier:
            return None

        candidates: list[Version] = []
        for raw in versions:
            try:
                candidates.append(Version(raw))
            except InvalidVersion:
                continue

        allowed = list(specifier.filter(candidates))
        if not allowed:
            return None

        return PackageRef(
            name=requirement.name, version=str(max(allowed)), ecosystem=PYPI
        )
