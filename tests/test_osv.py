"""Tests for the OSV.dev client.

Requests are answered by a mock transport, so the suite never touches the network.
"""

from typing import Any

import httpx
import pytest

from sbom_security.models import Dependency
from sbom_security.osv import OsvClient

EXPRESS = Dependency("express", "4.18.0", "pkg:npm/express@4.18.0")
ACCEPTS = Dependency("accepts", "1.3.8", "pkg:npm/accepts@1.3.8")

EXPRESS_ADVISORY = {
    "id": "GHSA-example-1",
    "aliases": ["CVE-2024-0001"],
    "summary": "Example vulnerability in express",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "express", "ecosystem": "npm"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.18.1"}],
                }
            ],
        }
    ],
}


class FakeOsv:
    """Answers OSV requests from canned data and records what was asked."""

    def __init__(
        self,
        batch_results: list[dict[str, Any]],
        records: dict[str, dict[str, Any]] | None = None,
    ):
        self.batch_results = batch_results
        self.records = records or {}
        self.paths: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": self.batch_results})
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=self.records[vuln_id])

    def client(self) -> OsvClient:
        return OsvClient(transport=httpx.MockTransport(self))


def test_asks_nothing_when_there_are_no_dependencies():
    fake = FakeOsv(batch_results=[])

    assert fake.client().find_vulnerabilities([]) == {}
    assert fake.paths == []


def test_maps_vulnerabilities_to_the_dependency_they_affect():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}, {}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])

    assert list(found) == [EXPRESS.purl]
    assert found[EXPRESS.purl][0].id == "GHSA-example-1"


def test_omits_dependencies_without_vulnerabilities():
    fake = FakeOsv(batch_results=[{}, {}])

    assert fake.client().find_vulnerabilities([EXPRESS, ACCEPTS]) == {}


def test_reports_the_cve_alias_summary_and_fix():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    vulnerability = fake.client().find_vulnerabilities([EXPRESS])[EXPRESS.purl][0]

    assert vulnerability.aliases == ("CVE-2024-0001",)
    assert vulnerability.summary == "Example vulnerability in express"
    assert vulnerability.fixed_version == "4.18.1"


def test_prefers_a_plain_severity_over_a_scoring_vector():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    vulnerability = fake.client().find_vulnerabilities([EXPRESS])[EXPRESS.purl][0]

    assert vulnerability.severity == "HIGH"


def test_falls_back_to_the_scoring_vector():
    advisory = {**EXPRESS_ADVISORY}
    del advisory["database_specific"]
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": advisory},
    )

    vulnerability = fake.client().find_vulnerabilities([EXPRESS])[EXPRESS.purl][0]

    assert vulnerability.severity == "CVSS:3.1/AV:N/AC:L"


def test_ignores_a_fix_belonging_to_a_different_package():
    advisory = {
        "id": "GHSA-example-2",
        "affected": [
            {
                "package": {"name": "some-other-package", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}],
            }
        ],
    }
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-2"}]}],
        records={"GHSA-example-2": advisory},
    )

    vulnerability = fake.client().find_vulnerabilities([EXPRESS])[EXPRESS.purl][0]

    assert vulnerability.fixed_version is None


def test_fetches_a_shared_advisory_only_once():
    fake = FakeOsv(
        batch_results=[
            {"vulns": [{"id": "GHSA-example-1"}]},
            {"vulns": [{"id": "GHSA-example-1"}]},
        ],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])

    assert set(found) == {EXPRESS.purl, ACCEPTS.purl}
    assert fake.paths.count("/v1/vulns/GHSA-example-1") == 1


def test_refuses_a_response_that_does_not_line_up_with_the_query():
    # A short response would attribute one package's vulnerabilities to another.
    fake = FakeOsv(batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}])

    with pytest.raises(RuntimeError, match="1 results for 2 queries"):
        fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])
