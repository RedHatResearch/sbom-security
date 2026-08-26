"""Tests for the work a worker performs.

The work is a plain async function taking its sources as an argument, so it is
exercised directly with no queue and no Redis anywhere in sight. That these tests need
neither is the point of keeping the queue at the edge.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from sbom_security.cache import SbomCache
from sbom_security.jobs import Sources, job_id, report_on_package
from sbom_security.osv import OsvClient
from sbom_security.registry import DepsDevClient

GRAPHS = {
    "express@4.18.0": {
        "nodes": [
            {"versionKey": {"name": "express", "version": "4.18.0"}, "relation": "SELF"},
            {"versionKey": {"name": "accepts", "version": "1.3.8"}, "relation": "DIRECT"},
        ]
    },
    "accepts@1.3.8": {
        "nodes": [
            {"versionKey": {"name": "accepts", "version": "1.3.8"}, "relation": "SELF"}
        ]
    },
}

ADVISORY = {
    "id": "GHSA-example-1",
    "aliases": ["CVE-2024-0001"],
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "express", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.18.1"}]}],
        }
    ],
}


def serve_graph(request: httpx.Request) -> httpx.Response:
    parts = str(request.url).split("/packages/")[1]
    name, rest = parts.split("/versions/")
    key = f"{name}@{rest.removesuffix(':dependencies')}"
    if key not in GRAPHS:
        return httpx.Response(404, json={})
    return httpx.Response(200, json=GRAPHS[key])


def serve_advisories(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-example-1"}]}
                    if "/express@" in query["package"]["purl"]
                    else {}
                    for query in queries
                ]
            },
        )
    return httpx.Response(200, json=ADVISORY)


class Callbacks:
    """Records what was delivered, and can be told to reject it."""

    def __init__(self, response_status: int = 200):
        self.response_status = response_status
        self.delivered: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.delivered.append(json.loads(request.content))
        return httpx.Response(self.response_status)


def sources_for(tmp_path: Path, callbacks: Callbacks | None = None) -> Sources:
    return Sources(
        cache=SbomCache(tmp_path),
        registry=DepsDevClient(transport=httpx.MockTransport(serve_graph)),
        osv=OsvClient(transport=httpx.MockTransport(serve_advisories)),
        transport=httpx.MockTransport(callbacks) if callbacks else None,
    )


def test_the_same_request_gets_the_same_identifier():
    assert job_id("express", "4.18.0", 3) == job_id("express", "4.18.0", 3)


def test_a_different_depth_is_a_different_request():
    # A shallower walk answers a different question about the same package.
    assert job_id("express", "4.18.0", 3) != job_id("express", "4.18.0", 1)


def test_a_different_version_is_a_different_request():
    assert job_id("express", "4.18.0", 3) != job_id("express", "4.19.2", 3)


def test_the_identifier_is_built_from_the_package_url():
    assert job_id("express", "4.18.0", 3).startswith("pkg:npm/express@4.18.0")


async def test_produces_a_report(tmp_path: Path):
    report = await report_on_package(
        "express", "4.18.0", depth=3, sources=sources_for(tmp_path)
    )

    assert report["target"] == "express@4.18.0"
    assert [dep["name"] for dep in report["dependencies"]] == ["express", "accepts"]
    # Still plain Python here, so tuples have not yet become JSON arrays.
    assert report["findings"][0]["vulnerabilities"][0]["aliases"] == ("CVE-2024-0001",)


async def test_fills_the_cache_along_the_way(tmp_path: Path):
    await report_on_package("express", "4.18.0", depth=3, sources=sources_for(tmp_path))

    cached = {path.name for path in tmp_path.glob("*.json")}

    # Both the package walked and the dependency it reached.
    assert len(cached) == 2


async def test_delivers_the_report_to_a_callback(tmp_path: Path):
    callbacks = Callbacks()

    await report_on_package(
        "express",
        "4.18.0",
        depth=3,
        callback_url="https://example.test/done",
        sources=sources_for(tmp_path, callbacks),
    )

    assert len(callbacks.delivered) == 1
    assert callbacks.delivered[0]["target"] == "express@4.18.0"


async def test_nothing_is_delivered_without_a_callback_url(tmp_path: Path):
    callbacks = Callbacks()

    await report_on_package(
        "express", "4.18.0", depth=3, sources=sources_for(tmp_path, callbacks)
    )

    assert callbacks.delivered == []


async def test_a_rejected_callback_does_not_lose_the_work(tmp_path: Path):
    callbacks = Callbacks(response_status=500)

    report = await report_on_package(
        "express",
        "4.18.0",
        depth=3,
        callback_url="https://example.test/done",
        sources=sources_for(tmp_path, callbacks),
    )

    # The result still comes back, ready to be collected instead.
    assert report["target"] == "express@4.18.0"


async def test_an_unknown_package_fails_the_work(tmp_path: Path):
    from sbom_security.registry import PackageNotFound  # pylint: disable=import-outside-toplevel

    with pytest.raises(PackageNotFound):
        await report_on_package(
            "nope", "9.9.9", depth=3, sources=sources_for(tmp_path)
        )
