"""Tests for the REST interface.

The vulnerability source is substituted, so the suite never touches the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from sbom_security.api import app, get_osv_client
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


@pytest.fixture(name="client")
def fixture_client():
    app.dependency_overrides[get_osv_client] = lambda: OsvClient(
        transport=httpx.MockTransport(handle)
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
    }
