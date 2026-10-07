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


# How much support a release line still receives. These correspond to the SPDX 3.0
# supportLevel vocabulary: active and supported to "support", limited to
# "limitedSupport", and eol to "endOfSupport".
ACTIVE = "active"
LIMITED = "limited"
SUPPORTED = "supported"
END_OF_LIFE = "eol"

# How a support status was arrived at.
PUBLISHED = "published"


@dataclass(frozen=True)
class Support:
    """Whether a dependency's release line still receives fixes, and on whose word.

    Projects publish support per release line rather than per version, so ``line``
    names the one this version belongs to: ``4`` for Express, ``4.2`` for Django.
    ``status`` is one of:

    - ``active`` — the line is in its main period of support.
    - ``limited`` — that period is over, but some fixes still come. ``phase`` says
      which, in the project's own words, such as ``Security Support``.
    - ``supported`` — fixes still come, but the project does not distinguish a main
      period of support from a later, reduced one.
    - ``eol`` — no fixes come at all.

    ``active_support_until`` and ``support_until`` are the dates those periods end,
    where they have been announced. The status is worked out from them when the
    report is produced rather than when the data was retrieved, so data kept for a
    while still gives the right answer.

    ``basis`` says how the answer was arrived at; ``published`` means the project
    publishes it. ``source`` is where to check it, and ``retrieved_at`` how old it is.
    """

    line: str
    status: str
    phase: str | None
    active_support_until: str | None
    support_until: str | None
    basis: str
    source: str
    retrieved_at: str


@dataclass(frozen=True)
class Dependency:
    """A resolved dependency at an exact version, normalized to a Package URL.

    ``support`` is None when no published support policy is known for the package,
    which is not the same as the package being unsupported.
    """

    name: str
    version: str
    purl: str
    ecosystem: str = NPM
    support: Support | None = None


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
    CVE number usually appears. ``url`` is a page a person can open to read the full
    record and its references.
    """

    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    severity: str | None = None
    fixed_version: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class Finding:
    """A dependency together with the vulnerabilities affecting it."""

    dependency: Dependency
    vulnerabilities: tuple[Vulnerability, ...]


# Raised when the shape of a report changes in a way a reader would notice.
SCHEMA_VERSION = "1.2"


@dataclass(frozen=True)
class Report:
    """The result of scanning one target.

    ``dependencies`` holds everything that was resolved, each with its support status
    where its project publishes one; ``findings`` holds only the subset with known
    vulnerabilities. ``truncated`` says whether a limit stopped the whole set from
    being examined, and ``unresolved`` names what could not be resolved at all — a
    local path, a git dependency, a package no index knows. Both exist so that a
    partial report is never mistaken for a clean one.

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
