"""Tests for reading resolved dependency graphs from deps.dev."""

import httpx
import pytest

from sbom_security.models import PackageRef
from sbom_security.registry import DepsDevClient, PackageNotFound

EXPRESS = PackageRef("express", "4.18.0")

# Shaped like a real deps.dev response: the package itself, its direct dependencies,
# and something reachable further down.
GRAPH = {
    "nodes": [
        {
            "versionKey": {"system": "NPM", "name": "express", "version": "4.18.0"},
            "relation": "SELF",
            "errors": [],
        },
        {
            "versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"},
            "relation": "DIRECT",
            "errors": [],
        },
        {
            "versionKey": {"system": "NPM", "name": "cookie", "version": "0.5.0"},
            "relation": "DIRECT",
            "errors": [],
        },
        {
            "versionKey": {"system": "NPM", "name": "mime-types", "version": "2.1.35"},
            "relation": "INDIRECT",
            "errors": [],
        },
    ],
    "edges": [{"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"}],
    "error": "",
}


def client_returning(status: int, payload: dict | None = None) -> DepsDevClient:
    def handle(request: httpx.Request) -> httpx.Response:
        handle.url = str(request.url)
        return httpx.Response(status, json=payload or {})

    return DepsDevClient(transport=httpx.MockTransport(handle))


def test_builds_the_dependency_graph_url():
    url = DepsDevClient().dependencies_url(EXPRESS)

    assert url == (
        "https://api.deps.dev/v3alpha/systems/npm/packages/express"
        "/versions/4.18.0:dependencies"
    )


def test_escapes_a_scoped_name_into_one_path_segment():
    url = DepsDevClient().dependencies_url(PackageRef("@babel/core", "7.20.12"))

    # The slash in the scope must not split the name across two path segments.
    assert "packages/%40babel%2Fcore/versions/7.20.12" in url


async def test_returns_only_the_direct_dependencies():
    client = client_returning(200, GRAPH)

    sbom = await client.direct_dependencies(EXPRESS)

    assert sbom.dependencies == (
        PackageRef("accepts", "1.3.8"),
        PackageRef("cookie", "0.5.0"),
    )


async def test_records_the_purl_of_the_package_itself():
    client = client_returning(200, GRAPH)

    sbom = await client.direct_dependencies(EXPRESS)

    assert sbom.purl == "pkg:npm/express@4.18.0"


async def test_a_package_with_no_dependencies_gives_an_empty_sbom():
    graph = {"nodes": [{"versionKey": {"name": "ms", "version": "2.1.3"}, "relation": "SELF"}]}
    client = client_returning(200, graph)

    sbom = await client.direct_dependencies(PackageRef("ms", "2.1.3"))

    assert sbom.dependencies == ()


async def test_reports_an_unknown_package_clearly():
    client = client_returning(404)

    with pytest.raises(PackageNotFound, match="express@4.18.0"):
        await client.direct_dependencies(EXPRESS)


async def test_raises_on_other_failures():
    client = client_returning(500)

    with pytest.raises(httpx.HTTPStatusError):
        await client.direct_dependencies(EXPRESS)
