"""Smoke test: the package imports and the models construct as expected."""

from sbom_security.models import Dependency, Finding, Report, Vulnerability


def test_report_holds_dependencies_and_findings():
    dependency = Dependency(name="express", version="4.18.0", purl="pkg:npm/express@4.18.0")
    vulnerability = Vulnerability(id="GHSA-example", severity="HIGH", fixed_version="4.18.1")
    finding = Finding(dependency=dependency, vulnerabilities=(vulnerability,))

    report = Report(
        target="example-project",
        dependencies=(dependency,),
        findings=(finding,),
    )

    assert report.dependencies[0].name == "express"
    assert report.findings[0].vulnerabilities[0].id == "GHSA-example"
