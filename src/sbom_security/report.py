"""Assemble the report for a scan target.

This is where the pieces meet: the dependencies a project has, normalized to Package
URLs, matched against the vulnerability source, and wrapped with enough context that
the answer can be read correctly later.
"""

from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from sbom_security.cache import SbomCache
from sbom_security.models import (
    NPM,
    PACKAGE,
    Dependency,
    Finding,
    PackageRef,
    Report,
    Summary,
    Target,
)
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies
from sbom_security.registry import DepsDevClient
from sbom_security.resolver import DEFAULT_DEPTH, resolve_tree


def now() -> str:
    """Return the current time, as the report records it."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def build_report(
    target: Target,
    dependencies: Sequence[Dependency],
    client: OsvClient,
    truncated: bool = False,
    unresolved: tuple[str, ...] = (),
) -> Report:
    """Match dependencies against the vulnerability source and collect the results.

    Every dependency is reported, since the inventory is useful on its own. Findings
    cover only those with known vulnerabilities, in the order the dependencies appear.
    """
    affected = await client.find_vulnerabilities(dependencies)
    findings = tuple(
        Finding(dependency=dependency, vulnerabilities=affected[dependency.purl])
        for dependency in dependencies
        if dependency.purl in affected
    )

    return Report(
        target=target,
        summary=Summary(
            dependencies=len(dependencies),
            vulnerable=len(findings),
            vulnerabilities=sum(len(finding.vulnerabilities) for finding in findings),
        ),
        dependencies=tuple(dependencies),
        findings=findings,
        generated_at=now(),
        truncated=truncated,
        unresolved=unresolved,
    )


async def report_for_package(
    name: str,
    version: str,
    cache: SbomCache,
    registry: DepsDevClient,
    osv: OsvClient,
    depth: int = DEFAULT_DEPTH,
) -> Report:
    """Resolve one package's dependencies and report on what they carry.

    Shared by the API and by the workers, which ask the same question by different
    routes: one holds the connection open, the other answers later.
    """
    resolution = await resolve_tree(
        PackageRef(name=name, version=version), cache=cache, client=registry, depth=depth
    )
    return await build_report(
        target=Target(name=f"{name}@{version}", ecosystem=NPM, source=PACKAGE),
        dependencies=to_dependencies(resolution.packages),
        client=osv,
        truncated=resolution.truncated,
        unresolved=resolution.unresolved,
    )


def as_dict(report: Report) -> dict[str, Any]:
    """Return the report as plain data, ready to be serialized as JSON."""
    return asdict(report)
