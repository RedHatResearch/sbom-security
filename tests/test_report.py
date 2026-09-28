"""Tests for report assembly and the shape of what comes out."""

import json
from typing import Any

import httpx

from sbom_security.models import LOCKFILE, NPM, SCHEMA_VERSION, Dependency, Target
from sbom_security.osv import OsvClient
from sbom_security.report import as_dict, build_report

EXPRESS = Dependency("express", "4.18.0", "pkg:npm/express@4.18.0")
ACCEPTS = Dependency("accepts", "1.3.8", "pkg:npm/accepts@1.3.8")

TARGET = Target(name="demo", ecosystem=NPM, source=LOCKFILE)

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


async def test_reports_every_dependency_even_when_unaffected():
    report = await build_report(TARGET, [EXPRESS, ACCEPTS], client_finding({"express"}))

    assert [dependency.name for dependency in report.dependencies] == [
        "express",
        "accepts",
    ]


async def test_findings_cover_only_the_affected_dependencies():
    report = await build_report(TARGET, [EXPRESS, ACCEPTS], client_finding({"express"}))

    assert len(report.findings) == 1
    assert report.findings[0].dependency.name == "express"
    assert report.findings[0].vulnerabilities[0].aliases == ("CVE-2024-0001",)


async def test_reports_no_findings_when_nothing_is_affected():
    report = await build_report(TARGET, [EXPRESS, ACCEPTS], client_finding(set()))

    assert report.findings == ()
    assert len(report.dependencies) == 2


async def test_the_summary_counts_what_the_arrays_hold():
    report = await build_report(TARGET, [EXPRESS, ACCEPTS], client_finding({"express"}))

    assert report.summary.dependencies == 2
    assert report.summary.vulnerable == 1
    assert report.summary.vulnerabilities == 1


async def test_the_report_says_where_its_versions_came_from():
    report = await build_report(TARGET, [EXPRESS], client_finding(set()))

    assert report.target.source == LOCKFILE
    assert report.target.ecosystem == NPM


async def test_the_report_records_when_and_by_what_it_was_made():
    # Vulnerability data changes daily, so an undated report cannot be compared
    # against a later one.
    report = await build_report(TARGET, [EXPRESS], client_finding(set()))

    assert report.generated_at
    assert report.tool == "sbom-security"
    assert report.schema_version == SCHEMA_VERSION


async def test_report_serializes_to_json():
    report = await build_report(TARGET, [EXPRESS], client_finding({"express"}))

    payload = json.loads(json.dumps(as_dict(report)))

    assert payload["target"]["name"] == "demo"
    assert payload["dependencies"][0]["purl"] == "pkg:npm/express@4.18.0"
    assert payload["findings"][0]["vulnerabilities"][0]["fixed_version"] == "4.18.1"
