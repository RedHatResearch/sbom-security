"""Assemble the report for a scan target.

This is where the pieces meet: the dependencies a project has, normalized to Package
URLs, matched against the vulnerability and support sources, and wrapped with enough
context that the answer can be read correctly later.
"""

import asyncio
from collections.abc import Sequence
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any

from sbom_security.cache import SbomCache
from sbom_security.image import SyftScanner, assess
from sbom_security.models import (
    IMAGE,
    NPM,
    OCI,
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
from sbom_security.support import SupportFinder


def now() -> str:
    """Return the current time, as the report records it."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def build_report(
    target: Target,
    dependencies: Sequence[Dependency],
    client: OsvClient,
    support: SupportFinder,
    truncated: bool = False,
    unresolved: tuple[str, ...] = (),
    not_assessed: tuple[str, ...] = (),
) -> Report:
    """Match dependencies against the vulnerability and support sources.

    Every dependency is reported, since the inventory is useful on its own, each with
    its support status where its project publishes one. Findings cover only those with
    known vulnerabilities, in the order the dependencies appear. Both sources are asked
    at once, since neither needs the other's answer.
    """
    affected, supported = await asyncio.gather(
        client.find_vulnerabilities(dependencies),
        support.find_support(dependencies),
    )
    reported = tuple(
        replace(dependency, support=supported.get(dependency.purl))
        for dependency in dependencies
    )
    findings = tuple(
        Finding(dependency=dependency, vulnerabilities=affected[dependency.purl])
        for dependency in reported
        if dependency.purl in affected
    )

    return Report(
        target=target,
        summary=Summary(
            dependencies=len(reported),
            vulnerable=len(findings),
            vulnerabilities=sum(len(finding.vulnerabilities) for finding in findings),
        ),
        dependencies=reported,
        findings=findings,
        generated_at=now(),
        truncated=truncated,
        unresolved=unresolved,
        not_assessed=not_assessed,
    )


async def report_for_package(
    name: str,
    version: str,
    cache: SbomCache,
    registry: DepsDevClient,
    osv: OsvClient,
    support: SupportFinder,
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
        support=support,
        truncated=resolution.truncated,
        unresolved=resolution.unresolved,
    )


async def report_for_image(
    reference: str,
    scanner: SyftScanner,
    osv: OsvClient,
    support: SupportFinder,
    limit: int,
) -> Report:
    """Find what a container image contains, and report on it.

    The image is read from its registry and never run. Packages that are not matched
    against vulnerability data yet, such as the operating system's, are listed as not
    assessed rather than left out.
    """
    inventory = await scanner.inventory(reference)
    dependencies, not_assessed = assess(inventory.packages)
    return await build_report(
        target=Target(name=inventory.reference, ecosystem=OCI, source=IMAGE),
        dependencies=dependencies[:limit],
        client=osv,
        support=support,
        truncated=len(dependencies) > limit,
        not_assessed=not_assessed,
    )


def as_dict(report: Report) -> dict[str, Any]:
    """Return the report as plain data, ready to be serialized as JSON."""
    return asdict(report)
