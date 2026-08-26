"""Data structures shared across the tool.

Plain dataclasses rather than a validation library: they are stdlib, trivial to
construct in tests, and FastAPI serializes them directly.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PackageRef:
    """A package at an exact version, as read from a lockfile.

    This is what a source file gives us, before normalization to a Package URL.
    """

    name: str
    version: str


@dataclass(frozen=True)
class Sbom:
    """The direct dependencies of one package version.

    Only direct dependencies are recorded. A published version's own dependencies
    never change, so this is permanently valid and can be cached indefinitely, and
    the depth of a dependency walk becomes a property of the walk rather than of
    anything stored here.
    """

    purl: str
    dependencies: tuple[PackageRef, ...]


@dataclass(frozen=True)
class Resolution:
    """Everything reached by walking a package's dependencies to a given depth.

    ``packages`` includes the root itself, since it can carry vulnerabilities of its
    own. ``truncated`` says the walk stopped at the depth limit with more still to
    expand, and ``unresolved`` names the packages whose own dependencies could not be
    looked up. Both exist so that a partial answer is never mistaken for a complete one.
    """

    root: PackageRef
    packages: tuple[PackageRef, ...]
    depth: int
    truncated: bool = False
    unresolved: tuple[str, ...] = ()


@dataclass(frozen=True)
class Dependency:
    """A resolved dependency at an exact version, normalized to a Package URL."""

    name: str
    version: str
    purl: str


@dataclass(frozen=True)
class Vulnerability:
    """A vulnerability affecting a specific dependency version.

    ``id`` is whatever the source calls the record, often a GitHub advisory id.
    ``aliases`` carries the other identifiers for the same issue, which is where the
    CVE number usually appears.
    """

    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    severity: str | None = None
    fixed_version: str | None = None


@dataclass(frozen=True)
class Finding:
    """A dependency together with the vulnerabilities affecting it."""

    dependency: Dependency
    vulnerabilities: tuple[Vulnerability, ...]


@dataclass(frozen=True)
class Report:
    """The result of scanning one target.

    ``dependencies`` holds everything that was resolved; ``findings`` holds only
    the subset with known vulnerabilities. ``truncated`` says whether a limit stopped
    the whole set from being examined, so that a partial report is never mistaken for
    a clean one.
    """

    target: str
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
    truncated: bool = False
