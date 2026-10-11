"""Tests for the OSV.dev client.

Requests are answered by a mock transport, so the suite never touches the network.
"""

import json
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
        self.queries: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if request.url.path == "/v1/querybatch":
            self.queries.extend(json.loads(request.content)["queries"])
            return httpx.Response(200, json={"results": self.batch_results})
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=self.records[vuln_id])

    def client(self) -> OsvClient:
        return OsvClient(transport=httpx.MockTransport(self))


async def test_asks_nothing_when_there_are_no_dependencies():
    fake = FakeOsv(batch_results=[])

    assert await fake.client().find_vulnerabilities([]) == {}
    assert fake.paths == []


async def test_maps_vulnerabilities_to_the_dependency_they_affect():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}, {}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])

    assert list(found) == [EXPRESS.purl]
    assert found[EXPRESS.purl][0].id == "GHSA-example-1"


async def test_omits_dependencies_without_vulnerabilities():
    fake = FakeOsv(batch_results=[{}, {}])

    assert await fake.client().find_vulnerabilities([EXPRESS, ACCEPTS]) == {}


async def test_reports_the_cve_alias_summary_and_fix():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS])
    vulnerability = found[EXPRESS.purl][0]

    assert vulnerability.aliases == ("CVE-2024-0001",)
    assert vulnerability.summary == "Example vulnerability in express"
    assert vulnerability.fixed_version == "4.18.1"


async def test_links_each_vulnerability_to_its_page():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS])

    assert found[EXPRESS.purl][0].url == "https://osv.dev/vulnerability/GHSA-example-1"


async def test_prefers_a_plain_severity_over_a_scoring_vector():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS])

    assert found[EXPRESS.purl][0].severity == "HIGH"


async def test_falls_back_to_the_scoring_vector():
    advisory = {**EXPRESS_ADVISORY}
    del advisory["database_specific"]
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}],
        records={"GHSA-example-1": advisory},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS])

    assert found[EXPRESS.purl][0].severity == "CVSS:3.1/AV:N/AC:L"


async def test_ignores_a_fix_belonging_to_a_different_package():
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

    found = await fake.client().find_vulnerabilities([EXPRESS])

    assert found[EXPRESS.purl][0].fixed_version is None


async def test_fetches_a_shared_advisory_only_once():
    fake = FakeOsv(
        batch_results=[
            {"vulns": [{"id": "GHSA-example-1"}]},
            {"vulns": [{"id": "GHSA-example-1"}]},
        ],
        records={"GHSA-example-1": EXPRESS_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])

    assert set(found) == {EXPRESS.purl, ACCEPTS.purl}
    assert fake.paths.count("/v1/vulns/GHSA-example-1") == 1


async def test_refuses_a_response_that_does_not_line_up_with_the_query():
    # A short response would attribute one package's vulnerabilities to another.
    fake = FakeOsv(batch_results=[{"vulns": [{"id": "GHSA-example-1"}]}])

    with pytest.raises(RuntimeError, match="1 results for 2 queries"):
        await fake.client().find_vulnerabilities([EXPRESS, ACCEPTS])


OPENSSL_LIBS = Dependency(
    "openssl-libs",
    "1:3.5.8-1.el9_8",
    "pkg:rpm/redhat/openssl-libs@3.5.8-1.el9_8?arch=x86_64&distro=rhel-9.8&epoch=1"
    "&upstream=openssl-3.5.8-1.el9_8.src.rpm",
    "rpm",
)
LIBSSL = Dependency(
    "libssl3t64",
    "3.5.7-1~deb13u3",
    "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7"
    "&upstream=openssl",
    "deb",
)

RHSA = {
    "id": "RHSA-2024:0310",
    "upstream": ["CVE-2023-5363"],
    "summary": "Red Hat Security Advisory: openssl security update",
    "affected": [
        {
            "package": {"name": "openssl", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1:3.0.7-25.el9_3"}]}],
        },
        {
            "package": {"name": "openssl-libs", "ecosystem": "Red Hat:enterprise_linux:9::baseos"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1:3.0.7-26.el9_3"}]}],
        },
    ],
}

DEBIAN_ADVISORY = {
    "id": "DEBIAN-CVE-2023-5363",
    "upstream": ["CVE-2023-5363"],
    "affected": [
        {
            "package": {"name": "openssl", "ecosystem": "Debian:12"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.0.11-1~deb12u2"}]}],
        },
        {
            "package": {"name": "openssl", "ecosystem": "Debian:13"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "3.0.11-1"}]}],
        },
    ],
}


async def test_a_language_package_is_asked_about_by_package_url():
    fake = FakeOsv(batch_results=[{}])

    await fake.client().find_vulnerabilities([EXPRESS])

    assert fake.queries == [{"package": {"purl": "pkg:npm/express@4.18.0"}}]


async def test_a_red_hat_package_is_asked_about_in_each_repository_with_its_epoch():
    fake = FakeOsv(batch_results=[{}, {}, {}])

    await fake.client().find_vulnerabilities([OPENSSL_LIBS])

    assert fake.queries == [
        {
            "package": {
                "name": "openssl-libs",
                "ecosystem": f"Red Hat:enterprise_linux:9::{repository}",
            },
            "version": "1:3.5.8-1.el9_8",
        }
        for repository in ("baseos", "appstream", "crb")
    ]


async def test_a_debian_package_is_asked_about_under_its_source_package_and_release():
    fake = FakeOsv(batch_results=[{}])

    await fake.client().find_vulnerabilities([LIBSSL])

    assert fake.queries == [
        {"package": {"name": "openssl", "ecosystem": "Debian:13"}, "version": "3.5.7-1~deb13u3"}
    ]


async def test_a_package_from_a_distribution_not_handled_is_not_asked_about():
    # Asked by Package URL instead, upstream advisories would answer it wrongly.
    ubuntu = Dependency(
        "libssl3",
        "3.0.2-0ubuntu1.18",
        "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04",
        "deb",
    )
    fake = FakeOsv(batch_results=[])

    assert await fake.client().find_vulnerabilities([ubuntu]) == {}
    assert fake.paths == []


async def test_the_cve_a_distribution_advisory_addresses_is_reported():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "RHSA-2024:0310"}]}, {}, {}],
        records={"RHSA-2024:0310": RHSA},
    )

    found = await fake.client().find_vulnerabilities([OPENSSL_LIBS])

    assert found[OPENSSL_LIBS.purl][0].aliases == ("CVE-2023-5363",)


async def test_the_fix_is_the_one_for_the_package_asked_about():
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "RHSA-2024:0310"}]}, {}, {}],
        records={"RHSA-2024:0310": RHSA},
    )

    found = await fake.client().find_vulnerabilities([OPENSSL_LIBS])

    assert found[OPENSSL_LIBS.purl][0].fixed_version == "1:3.0.7-26.el9_3"


async def test_the_fix_is_the_one_for_the_release_asked_about():
    # The same advisory covers several Debian releases, each fixed in its own version.
    fake = FakeOsv(
        batch_results=[{"vulns": [{"id": "DEBIAN-CVE-2023-5363"}]}],
        records={"DEBIAN-CVE-2023-5363": DEBIAN_ADVISORY},
    )

    found = await fake.client().find_vulnerabilities([LIBSSL])

    assert found[LIBSSL.purl][0].fixed_version == "3.0.11-1"


async def test_an_advisory_answering_several_repositories_is_reported_once():
    fake = FakeOsv(
        batch_results=[
            {"vulns": [{"id": "RHSA-2024:0310"}]},
            {"vulns": [{"id": "RHSA-2024:0310"}]},
            {},
        ],
        records={"RHSA-2024:0310": RHSA},
    )

    found = await fake.client().find_vulnerabilities([OPENSSL_LIBS])

    assert [vulnerability.id for vulnerability in found[OPENSSL_LIBS.purl]] == [
        "RHSA-2024:0310"
    ]
