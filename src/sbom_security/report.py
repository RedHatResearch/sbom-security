"""Assemble the report for a scan target.

This is where the three steps meet: read the dependencies, normalize them to Package
URLs, and ask the vulnerability source which of them are affected.
"""

from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sbom_security.lockfile import parse_package_lock
from sbom_security.models import Dependency, Finding, Report
from sbom_security.osv import OsvClient
from sbom_security.purl import to_dependencies


def report_for_lockfile(
    path: Path, client: OsvClient | None = None, target: str | None = None
) -> Report:
    """Produce a report for a repository from its npm lockfile.

    A repository has no version of its own, so the lockfile is the authority on what
    is actually installed: it already pins every dependency in the tree.
    """
    dependencies = to_dependencies(parse_package_lock(path))
    return build_report(
        target=target or str(path),
        dependencies=dependencies,
        client=client or OsvClient(),
    )


def build_report(
    target: str, dependencies: Sequence[Dependency], client: OsvClient
) -> Report:
    """Match dependencies against the vulnerability source and collect the results.

    Every dependency is reported, since the inventory is useful on its own. Findings
    cover only those with known vulnerabilities, in the order the dependencies appear.
    """
    affected = client.find_vulnerabilities(dependencies)
    findings = tuple(
        Finding(dependency=dependency, vulnerabilities=affected[dependency.purl])
        for dependency in dependencies
        if dependency.purl in affected
    )
    return Report(target=target, dependencies=tuple(dependencies), findings=findings)


def as_dict(report: Report) -> dict[str, Any]:
    """Return the report as plain data, ready to be serialized as JSON."""
    return asdict(report)
