"""Tests for the REST interface.

Every external source is substituted, so the suite never touches the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from sbom_security.api import (
    app,
    get_cache,
    get_github_source,
    get_npm_registry,
    get_osv_client,
    get_pypi_index,
    get_queue,
    get_registry_client,
    get_support_source,
)
from sbom_security.cache import SbomCache
from sbom_security.endoflife import EndOfLifeClient
from sbom_security.github import GitHubSource
from sbom_security.jobs import (
    COMPLETE,
    NOT_FOUND,
    QUEUED,
    JobState,
    QueueOverview,
    job_id,
)
from sbom_security.npm import NpmRegistry
from sbom_security.osv import OsvClient
from sbom_security.pypi import PyPiIndex
from sbom_security.registry import DepsDevClient

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

# express depends on accepts; nothing else has dependencies. Both published versions
# are here, since a request that names no version resolves to the newest.
GRAPHS = {
    "express@4.18.0": {
        "nodes": [
            {"versionKey": {"name": "express", "version": "4.18.0"}, "relation": "SELF"},
            {"versionKey": {"name": "accepts", "version": "1.3.8"}, "relation": "DIRECT"},
        ]
    },
    "express@5.0.0": {
        "nodes": [
            {"versionKey": {"name": "express", "version": "5.0.0"}, "relation": "SELF"},
            {"versionKey": {"name": "accepts", "version": "1.3.8"}, "relation": "DIRECT"},
        ]
    },
    "accepts@1.3.8": {
        "nodes": [
            {"versionKey": {"name": "accepts", "version": "1.3.8"}, "relation": "SELF"}
        ]
    },
    "%40babel%2Fcore@7.20.12": {
        "nodes": [
            {"versionKey": {"name": "@babel/core", "version": "7.20.12"},
             "relation": "SELF"}
        ]
    },
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


MANIFEST = {"name": "manifest-project", "dependencies": {"express": "^4.18.0"}}

PUBLISHED_VERSIONS = {
    "express": ["4.17.0", "4.18.0", "5.0.0"],
    "@babel/core": ["7.20.12"],
}


REQUIREMENTS_TXT = "django==4.2.0\n-r base.txt\n"

RELEASED_VERSIONS = {"django": ["4.1.0", "4.2.0"]}


def serve_repository_files(request: httpx.Request) -> httpx.Response:
    """Serve repository files.

    `OWASP/NodeGoat` has a lockfile. `expressjs/express` has only a manifest, which
    exercises npm range resolution. `pallets/flask` has only a requirements file,
    which exercises the Python path. `empty/repo` has none of them.
    """
    filename = request.url.path.rsplit("/", 1)[-1]

    if "empty" in request.url.path:
        return httpx.Response(404, text="404: Not Found")

    if "pallets" in request.url.path:
        if filename == "requirements.txt":
            return httpx.Response(200, text=REQUIREMENTS_TXT)
        return httpx.Response(404, text="404: Not Found")

    if "expressjs" in request.url.path:
        if filename == "package.json":
            return httpx.Response(200, json=MANIFEST)
        return httpx.Response(404, text="404: Not Found")

    if filename == "package-lock.json":
        return httpx.Response(200, json=LOCKFILE)
    return httpx.Response(404, text="404: Not Found")


def serve_released_versions(request: httpx.Request) -> httpx.Response:
    """Serve the Python package index's release list."""
    name = request.url.path.split("/")[2]
    if name not in RELEASED_VERSIONS:
        return httpx.Response(404, json={})
    return httpx.Response(
        200, json={"releases": {version: [] for version in RELEASED_VERSIONS[name]}}
    )


def serve_published_versions(request: httpx.Request) -> httpx.Response:
    """Serve the npm registry's version list."""
    name = request.url.path.lstrip("/").replace("%2F", "/")
    if name not in PUBLISHED_VERSIONS:
        return httpx.Response(404, json={})
    return httpx.Response(
        200, json={"versions": {version: {} for version in PUBLISHED_VERSIONS[name]}}
    )


def serve_graph(request: httpx.Request) -> httpx.Response:
    """Serve a canned dependency graph, or 404 for an unknown package."""
    parts = str(request.url).split("/packages/")[1]
    name, rest = parts.split("/versions/")
    key = f"{name}@{rest.removesuffix(':dependencies')}"
    if key not in GRAPHS:
        return httpx.Response(404, json={})
    return httpx.Response(200, json=GRAPHS[key])


class FakeQueue:
    """Stands in for the work queue, recording what was submitted."""

    def __init__(self):
        self.submitted: list[tuple[str, str, int | None, str | None]] = []
        self.states: dict[str, JobState] = {}
        self.overview_result = QueueOverview(queued=0, running=())

    async def submit(
        self,
        name: str,
        version: str,
        depth: int | None,
        callback_url: str | None = None,
    ) -> str:
        identifier = job_id(name, version, depth)
        self.submitted.append((name, version, depth, callback_url))
        self.states.setdefault(identifier, JobState(id=identifier, status=QUEUED))
        return identifier

    async def state(self, identifier: str) -> JobState:
        return self.states.get(identifier, JobState(id=identifier, status=NOT_FOUND))

    async def overview(self) -> QueueOverview:
        return self.overview_result


@pytest.fixture(name="queue")
def fixture_queue():
    return FakeQueue()


@pytest.fixture(name="client")
def fixture_client(tmp_path: Path, queue: FakeQueue, support_source: EndOfLifeClient):
    app.dependency_overrides[get_osv_client] = lambda: OsvClient(
        transport=httpx.MockTransport(handle)
    )
    app.dependency_overrides[get_github_source] = lambda: GitHubSource(
        transport=httpx.MockTransport(serve_repository_files)
    )
    app.dependency_overrides[get_registry_client] = lambda: DepsDevClient(
        transport=httpx.MockTransport(serve_graph)
    )
    app.dependency_overrides[get_npm_registry] = lambda: NpmRegistry(
        transport=httpx.MockTransport(serve_published_versions)
    )
    app.dependency_overrides[get_pypi_index] = lambda: PyPiIndex(
        transport=httpx.MockTransport(serve_released_versions)
    )
    app.dependency_overrides[get_cache] = lambda: SbomCache(tmp_path)
    app.dependency_overrides[get_support_source] = lambda: support_source
    app.dependency_overrides[get_queue] = lambda: queue
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
    assert payload["target"]["name"] == "example-project"
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
    payload = response.json()
    assert payload["dependencies"] == []
    assert payload["findings"] == []
    assert payload["truncated"] is False
    assert payload["unresolved"] == []
    assert payload["summary"] == {
        "dependencies": 0,
        "vulnerable": 0,
        "vulnerabilities": 0,
    }


def test_a_report_says_which_ecosystem_and_source_it_came_from(client):
    payload = client.post("/reports/npm-lockfile", json=LOCKFILE).json()

    assert payload["target"] == {
        "name": "example-project",
        "ecosystem": "npm",
        "source": "lockfile",
    }


def test_a_manifest_report_is_marked_as_resolved_rather_than_installed(client):
    # The distinction matters: a manifest says what you would get today, a lockfile
    # says what you actually have, and the second is usually older.
    payload = client.get(
        "/reports/github", params={"owner": "expressjs", "repo": "express"}
    ).json()

    assert payload["target"]["source"] == "manifest"


def test_a_python_report_names_its_ecosystem(client):
    payload = client.get(
        "/reports/github", params={"owner": "pallets", "repo": "flask"}
    ).json()

    assert payload["target"]["ecosystem"] == "pypi"
    assert payload["dependencies"][0]["ecosystem"] == "pypi"


def test_a_report_carries_a_schema_version_and_a_timestamp(client):
    payload = client.post("/reports/npm-lockfile", json=LOCKFILE).json()

    assert payload["schema_version"] == "1.2"
    assert payload["tool"] == "sbom-security"
    assert payload["generated_at"]


def test_each_dependency_says_whether_it_is_still_supported(client):
    payload = client.post("/reports/npm-lockfile", json=LOCKFILE).json()
    by_name = {dependency["name"]: dependency for dependency in payload["dependencies"]}

    assert by_name["express"]["support"]["line"] == "4"
    assert by_name["express"]["support"]["status"] == "supported"
    # No published policy covers accepts; the report says so rather than guessing.
    assert by_name["accepts"]["support"] is None


def test_a_package_report_carries_support_status_too(client):
    payload = client.get(
        "/reports/npm-package", params={"name": "express", "version": "4.18.0"}
    ).json()

    assert payload["dependencies"][0]["support"]["status"] == "supported"


def test_reports_on_a_package_and_its_dependencies(client):
    response = client.get(
        "/reports/npm-package", params={"name": "express", "version": "4.18.0"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"]["name"] == "express@4.18.0"
    # The package itself, plus what it depends on.
    assert [dep["name"] for dep in payload["dependencies"]] == ["express", "accepts"]


def test_package_findings_name_the_cve(client):
    payload = client.get(
        "/reports/npm-package", params={"name": "express", "version": "4.18.0"}
    ).json()

    assert payload["findings"][0]["vulnerabilities"][0]["aliases"] == ["CVE-2024-0001"]


def test_a_package_walked_only_one_level_is_marked_truncated(client):
    payload = client.get(
        "/reports/npm-package",
        params={"name": "express", "version": "4.18.0", "depth": 1},
    ).json()

    assert payload["truncated"] is True


def test_package_report_accepts_a_scoped_name(client):
    response = client.get(
        "/reports/npm-package", params={"name": "@babel/core", "version": "7.20.12"}
    )

    assert response.status_code == 200
    assert response.json()["dependencies"][0]["name"] == "@babel/core"


def test_an_unknown_package_is_reported_as_not_found(client):
    response = client.get(
        "/reports/npm-package", params={"name": "nope", "version": "9.9.9"}
    )

    assert response.status_code == 404


def test_a_package_without_a_version_gets_the_newest(client):
    # Registering once and not re-registering at every release is the point.
    response = client.get("/reports/npm-package", params={"name": "express"})

    assert response.status_code == 200
    assert response.json()["target"]["name"] == "express@5.0.0"


def test_a_range_gets_the_newest_within_it(client):
    response = client.get(
        "/reports/npm-package", params={"name": "express", "version": "^4.0.0"}
    )

    # 5.0.0 exists but crosses the major boundary.
    assert response.json()["target"]["name"] == "express@4.18.0"


def test_the_report_names_the_version_it_settled_on(client):
    payload = client.get("/reports/npm-package", params={"name": "express"}).json()

    # Not "latest" — what latest meant at the time, which generated_at dates.
    assert payload["target"]["name"] == "express@5.0.0"
    assert payload["generated_at"]


def test_a_version_that_was_never_published_is_reported_clearly(client):
    response = client.get(
        "/reports/npm-package", params={"name": "express", "version": "99.0.0"}
    )

    assert response.status_code == 404
    assert "99.0.0" in response.json()["detail"]


def test_submitted_work_names_a_version_not_a_range(client, queue):
    # Two requests months apart must not share one job and one stale answer.
    client.post("/jobs/npm-package", params={"name": "express"})

    assert queue.submitted == [("express", "5.0.0", None, None)]


def test_reports_on_a_github_repository(client):
    response = client.get(
        "/reports/github", params={"owner": "OWASP", "repo": "NodeGoat"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"]["name"] == "OWASP/NodeGoat@HEAD"
    assert len(payload["dependencies"]) == 5
    assert payload["findings"][0]["dependency"]["name"] == "express"


def test_github_report_names_the_ref_that_was_read(client):
    response = client.get(
        "/reports/github",
        params={"owner": "OWASP", "repo": "NodeGoat", "ref": "master"},
    )

    assert response.json()["target"]["name"] == "OWASP/NodeGoat@master"


def test_a_repository_without_a_lockfile_falls_back_to_its_manifest(client):
    # expressjs/express commits no lockfile, as most libraries do not.
    response = client.get(
        "/reports/github", params={"owner": "expressjs", "repo": "express"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"]["name"] == "expressjs/express@HEAD"
    # The declared range ^4.18.0 resolved to the highest published match.
    assert payload["dependencies"][0]["name"] == "express"
    assert payload["dependencies"][0]["version"] == "4.18.0"


def test_a_manifest_report_still_finds_vulnerabilities(client):
    payload = client.get(
        "/reports/github", params={"owner": "expressjs", "repo": "express"}
    ).json()

    assert payload["findings"][0]["vulnerabilities"][0]["aliases"] == ["CVE-2024-0001"]


def test_a_python_repository_is_read_from_its_requirements(client):
    response = client.get(
        "/reports/github", params={"owner": "pallets", "repo": "flask"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["dependencies"][0]["name"] == "django"
    assert payload["dependencies"][0]["purl"] == "pkg:pypi/django@4.2.0"


def test_a_python_report_names_what_it_could_not_follow(client):
    # The requirements file points at another with -r, which is not followed.
    payload = client.get(
        "/reports/github", params={"owner": "pallets", "repo": "flask"}
    ).json()

    assert "-r base.txt" in payload["unresolved"]


def test_a_repository_with_no_known_dependency_file_is_not_found(client):
    response = client.get("/reports/github", params={"owner": "empty", "repo": "repo"})

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "package-lock.json" in detail
    assert "requirements.txt" in detail


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


def test_submitting_a_package_returns_immediately(client, queue):
    response = client.post(
        "/jobs/npm-package", params={"name": "express", "version": "4.18.0"}
    )

    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    # No depth given means the whole tree.
    assert queue.submitted == [("express", "4.18.0", None, None)]


def test_the_queue_reports_what_is_waiting_and_running(client, queue):
    queue.overview_result = QueueOverview(queued=3, running=("job-a", "job-b"))

    response = client.get("/queue")

    assert response.status_code == 200
    assert response.json() == {"queued": 3, "running": ["job-a", "job-b"]}


def test_an_idle_queue_reports_nothing_waiting(client):
    assert client.get("/queue").json() == {"queued": 0, "running": []}


def test_a_submission_says_where_to_collect_the_result(client):
    response = client.post(
        "/jobs/npm-package", params={"name": "express", "version": "4.18.0"}
    )

    assert response.headers["Location"] == f"/jobs/{response.json()['id']}"


def test_the_same_request_twice_is_queued_once(client, queue):
    first = client.post(
        "/jobs/npm-package", params={"name": "express", "version": "4.18.0"}
    ).json()
    second = client.post(
        "/jobs/npm-package", params={"name": "express", "version": "4.18.0"}
    ).json()

    # Both callers hold the same identifier and wait on the same piece of work.
    assert first["id"] == second["id"]


def test_a_callback_url_is_passed_to_the_worker(client, queue):
    client.post(
        "/jobs/npm-package",
        params={
            "name": "express",
            "version": "4.18.0",
            "callback_url": "https://example.test/done",
        },
    )

    assert queue.submitted[0][3] == "https://example.test/done"


def test_a_finished_job_hands_back_its_report(client, queue):
    identifier = job_id("express", "4.18.0", 3)
    queue.states[identifier] = JobState(
        id=identifier, status=COMPLETE, result={"target": "express@4.18.0"}
    )

    response = client.get(f"/jobs/{identifier}")

    assert response.status_code == 200
    assert response.json()["result"]["target"] == "express@4.18.0"


def test_an_unfinished_job_reports_its_status_without_a_result(client, queue):
    identifier = job_id("express", "4.18.0", 3)
    queue.states[identifier] = JobState(id=identifier, status="in_progress")

    payload = client.get(f"/jobs/{identifier}").json()

    assert payload["status"] == "in_progress"
    assert payload["result"] is None


def test_an_unknown_job_is_reported_as_not_found(client):
    response = client.get("/jobs/pkg:npm/nothing@1.0.0@depth=3")

    assert response.status_code == 404


def test_a_failed_job_says_why(client, queue):
    identifier = job_id("nope", "9.9.9", 3)
    queue.states[identifier] = JobState(
        id=identifier,
        status="failed",
        error="PackageNotFound: nope@9.9.9 is not known to deps.dev",
    )

    payload = client.get(f"/jobs/{identifier}").json()

    assert payload["status"] == "failed"
    assert "PackageNotFound" in payload["error"]
