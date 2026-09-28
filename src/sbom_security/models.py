"""Data structures shared across the tool.

Plain dataclasses rather than a validation library: they are stdlib, trivial to
construct in tests, and FastAPI serializes them directly.
"""

from dataclasses import dataclass


# Package URL type strings, which are also what deps.dev calls these ecosystems.
NPM = "npm"
PYPI = "pypi"


@dataclass(frozen=True)
class PackageRef:
    """A package at an exact version, as read from a dependency file.

    This is what a source file gives us, before normalization to a Package URL. The
    ecosystem travels with the reference because a name alone is ambiguous: an npm
    package and a PyPI package can share one, and they are not the same software.
    """

    name: str
    version: str
    ecosystem: str = NPM


@dataclass(frozen=True)
class Requirement:
    """A dependency as a manifest declares it: a name and a range, not a version.

    ``express: ^4.18.0`` says which versions would be acceptable, not which one is
    installed. Matching against vulnerability data needs the latter, so a requirement
    has to be resolved before it is of any use.
    """

    name: str
    range: str
    ecosystem: str = NPM


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

    root: PackageRef | None
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
    ecosystem: str = NPM


# Where the versions in a report came from. The distinction matters: these answer
# different questions, and a reader who mistakes one for the other draws the wrong
# conclusion from the same number of findings.
LOCKFILE = "lockfile"
MANIFEST = "manifest"
PACKAGE = "package"


@dataclass(frozen=True)
class Target:
    """What was scanned, and how its versions were arrived at.

    ``source`` says which question the report answers:

    - ``lockfile`` — the versions actually installed. What the project has.
    - ``manifest`` — declared ranges resolved to the newest version that satisfies
      them. What the project would get if it installed today, which is usually newer,
      and therefore usually cleaner, than what it really runs.
    - ``package`` — one package and the dependencies its released version declares.
    """

    name: str
    ecosystem: str
    source: str


@dataclass(frozen=True)
class Summary:
    """Counts a reader would otherwise have to work out from the arrays."""

    dependencies: int
    vulnerable: int
    vulnerabilities: int


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


# Raised when the shape of a report changes in a way a reader would notice.
SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class Report:
    """The result of scanning one target.

    ``dependencies`` holds everything that was resolved; ``findings`` holds only the
    subset with known vulnerabilities. ``truncated`` says whether a limit stopped the
    whole set from being examined, and ``unresolved`` names what could not be resolved
    at all — a local path, a git dependency, a package no index knows. Both exist so
    that a partial report is never mistaken for a clean one.

    ``generated_at`` and ``tool`` record when the answer was produced and by what.
    Vulnerability data changes daily, so a report without a date is not reproducible
    and cannot be compared against a later one.
    """

    target: Target
    summary: Summary
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
    generated_at: str
    truncated: bool = False
    unresolved: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    tool: str = "sbom-security"
