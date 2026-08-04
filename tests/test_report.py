"""Tests for report assembly, including the path from a lockfile to a finished report."""

import json
from pathlib import Path
from typing import Any

import httpx

from sbom_security.models import Dependency
from sbom_security.osv import OsvClient
from sbom_security.report import as_dict, build_report, report_for_lockfile

FIXTURE = Path(__file__).parent / "data" / "package-lock.json"

EXPRESS = Dependency("express", "4.18.0", "pkg:npm/express@4.18.0")
ACCEPTS = Dependency("accepts", "1.3.8", "pkg:npm/accepts@1.3.8")

ADVISORY = {
    "id": "GHSA-example-1",
    "aliases": ["CVE-2024-0001"],
    "summary": "Example vulnerability",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "express", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.18.1"}]}],
        }
    ],
}


def client_finding(affected_names: set[str]) -> OsvClient:
    """An OSV client that reports one advisory against the named packages."""

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results: list[dict[str, Any]] = []
            for query in queries:
                purl = query["package"]["purl"]
                hit = any(f"/{name}@" in purl for name in affected_names)
                results.append({"vulns": [{"id": "GHSA-example-1"}]} if hit else {})
            return httpx.Response(200, json={"results": results})
        return httpx.Response(200, json=ADVISORY)

    return OsvClient(transport=httpx.MockTransport(handle))


def test_reports_every_dependency_even_when_unaffected():
    report = build_report("demo", [EXPRESS, ACCEPTS], client_finding({"express"}))

    assert [dependency.name for dependency in report.dependencies] == [
        "express",
        "accepts",
    ]


def test_findings_cover_only_the_affected_dependencies():
    report = build_report("demo", [EXPRESS, ACCEPTS], client_finding({"express"}))

    assert len(report.findings) == 1
    assert report.findings[0].dependency.name == "express"
    assert report.findings[0].vulnerabilities[0].aliases == ("CVE-2024-0001",)


def test_reports_no_findings_when_nothing_is_affected():
    report = build_report("demo", [EXPRESS, ACCEPTS], client_finding(set()))

    assert report.findings == ()
    assert len(report.dependencies) == 2


def test_reads_a_lockfile_and_reports_against_it():
    report = report_for_lockfile(
        FIXTURE, client=client_finding({"express"}), target="example-project"
    )

    assert report.target == "example-project"
    assert len(report.dependencies) == 5
    assert [finding.dependency.name for finding in report.findings] == ["express"]


def test_report_serializes_to_json():
    report = build_report("demo", [EXPRESS], client_finding({"express"}))

    payload = json.loads(json.dumps(as_dict(report)))

    assert payload["target"] == "demo"
    assert payload["dependencies"][0]["purl"] == "pkg:npm/express@4.18.0"
    assert payload["findings"][0]["vulnerabilities"][0]["fixed_version"] == "4.18.1"
