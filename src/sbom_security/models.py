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
class Dependency:
    """A resolved dependency at an exact version, normalized to a Package URL."""

    name: str
    version: str
    purl: str


@dataclass(frozen=True)
class Vulnerability:
    """A vulnerability affecting a specific dependency version."""

    id: str
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
    the subset with known vulnerabilities.
    """

    target: str
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
