"""Tests for the REST interface.

The vulnerability source is substituted, so the suite never touches the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from sbom_security.api import app, get_github_source, get_osv_client
from sbom_security.github import GitHubSource
from sbom_security.osv import OsvClient

LOCKFILE = json.loads((Path(__file__).parent / "data" / "package-lock.json").read_text())

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


def handle(request: httpx.Request) -> httpx.Response:
    """Report the example advisory against express, and nothing against the rest."""
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        results: list[dict[str, Any]] = [
            {"vulns": [{"id": "GHSA-example-1"}]}
            if "/express@" in query["package"]["purl"]
            else {}
            for query in queries
        ]
        return httpx.Response(200, json={"results": results})
    return httpx.Response(200, json=ADVISORY)


def serve_lockfile(request: httpx.Request) -> httpx.Response:
    """Serve the fixture lockfile for any repository except a known-missing one."""
    if "expressjs" in request.url.path:
        return httpx.Response(404, text="404: Not Found")
    return httpx.Response(200, json=LOCKFILE)


@pytest.fixture(name="client")
def fixture_client():
    app.dependency_overrides[get_osv_client] = lambda: OsvClient(
        transport=httpx.MockTransport(handle)
    )
    app.dependency_overrides[get_github_source] = lambda: GitHubSource(
        transport=httpx.MockTransport(serve_lockfile)
    )
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health_reports_ok(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_reports_on_a_submitted_lockfile(client):
    response = client.post("/reports/npm-lockfile", json=LOCKFILE)

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "example-project"
    assert len(payload["dependencies"]) == 5


def test_findings_name_the_affected_dependency_and_its_cve(client):
    payload = client.post("/reports/npm-lockfile", json=LOCKFILE).json()

    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["dependency"]["name"] == "express"
    assert finding["vulnerabilities"][0]["aliases"] == ["CVE-2024-0001"]
    assert finding["vulnerabilities"][0]["fixed_version"] == "4.18.1"


def test_accepts_a_lockfile_with_no_dependencies(client):
    response = client.post("/reports/npm-lockfile", json={"name": "empty"})

    assert response.status_code == 200
    assert response.json() == {
        "target": "empty",
        "dependencies": [],
        "findings": [],
        "truncated": False,
    }


def test_reports_on_a_single_package(client):
    response = client.get(
        "/reports/npm-package", params={"name": "express", "version": "4.18.0"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "express@4.18.0"
    assert payload["dependencies"] == [
        {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"}
    ]
    assert payload["findings"][0]["vulnerabilities"][0]["aliases"] == ["CVE-2024-0001"]


def test_single_package_report_is_empty_when_unaffected(client):
    response = client.get(
        "/reports/npm-package", params={"name": "accepts", "version": "1.3.8"}
    )

    assert response.status_code == 200
    assert response.json()["findings"] == []


def test_single_package_accepts_a_scoped_name(client):
    response = client.get(
        "/reports/npm-package", params={"name": "@babel/core", "version": "7.20.12"}
    )

    assert response.status_code == 200
    assert response.json()["dependencies"][0]["name"] == "@babel/core"


def test_single_package_requires_a_version(client):
    response = client.get("/reports/npm-package", params={"name": "express"})

    assert response.status_code == 422


def test_reports_on_a_github_repository(client):
    response = client.get(
        "/reports/github", params={"owner": "OWASP", "repo": "NodeGoat"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "OWASP/NodeGoat@HEAD"
    assert len(payload["dependencies"]) == 5
    assert payload["findings"][0]["dependency"]["name"] == "express"


def test_github_report_names_the_ref_that_was_read(client):
    response = client.get(
        "/reports/github",
        params={"owner": "OWASP", "repo": "NodeGoat", "ref": "master"},
    )

    assert response.json()["target"] == "OWASP/NodeGoat@master"


def test_missing_lockfile_is_reported_as_not_found(client):
    response = client.get(
        "/reports/github", params={"owner": "expressjs", "repo": "express"}
    )

    assert response.status_code == 404
    assert "package-lock.json" in response.json()["detail"]


def test_a_report_cut_short_by_the_limit_says_so(client):
    response = client.post("/reports/npm-lockfile", json=LOCKFILE, params={"limit": 2})

    payload = response.json()
    assert payload["truncated"] is True
    assert len(payload["dependencies"]) == 2


def test_a_complete_report_is_not_marked_truncated(client):
    response = client.post("/reports/npm-lockfile", json=LOCKFILE, params={"limit": 50})

    assert response.json()["truncated"] is False


def test_the_limit_must_be_positive(client):
    response = client.post("/reports/npm-lockfile", json=LOCKFILE, params={"limit": 0})

    assert response.status_code == 422
