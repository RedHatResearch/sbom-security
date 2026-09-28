"""Smoke test: the package imports and the models construct as expected."""

from sbom_security.models import (
    LOCKFILE,
    NPM,
    Dependency,
    Finding,
    Report,
    Summary,
    Target,
    Vulnerability,
)


def test_report_holds_dependencies_and_findings():
    dependency = Dependency(name="express", version="4.18.0", purl="pkg:npm/express@4.18.0")
    vulnerability = Vulnerability(id="GHSA-example", severity="HIGH", fixed_version="4.18.1")
    finding = Finding(dependency=dependency, vulnerabilities=(vulnerability,))

    report = Report(
        target=Target(name="example-project", ecosystem=NPM, source=LOCKFILE),
        summary=Summary(dependencies=1, vulnerable=1, vulnerabilities=1),
        dependencies=(dependency,),
        findings=(finding,),
        generated_at="2026-01-01T00:00:00+00:00",
    )

    assert report.dependencies[0].name == "express"
    assert report.findings[0].vulnerabilities[0].id == "GHSA-example"
    assert report.target.source == LOCKFILE
