"""Tests for building SBOMs through the cache."""

from pathlib import Path

import httpx

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef, Sbom
from sbom_security.registry import DepsDevClient
from sbom_security.resolver import sbom_for

EXPRESS = PackageRef("express", "4.18.0")

GRAPH = {
    "nodes": [
        {
            "versionKey": {"system": "NPM", "name": "express", "version": "4.18.0"},
            "relation": "SELF",
        },
        {
            "versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"},
            "relation": "DIRECT",
        },
    ]
}


class CountingRegistry:
    """A deps.dev client that records how often it was asked."""

    def __init__(self):
        self.calls = 0

    def client(self) -> DepsDevClient:
        def handle(_: httpx.Request) -> httpx.Response:
            self.calls += 1
            return httpx.Response(200, json=GRAPH)

        return DepsDevClient(transport=httpx.MockTransport(handle))


async def test_builds_and_stores_an_sbom_that_is_not_cached(tmp_path: Path):
    cache = SbomCache(tmp_path)
    registry = CountingRegistry()

    sbom = await sbom_for(EXPRESS, cache, registry.client())

    assert sbom.dependencies == (PackageRef("accepts", "1.3.8"),)
    assert cache.has("pkg:npm/express@4.18.0")
    assert registry.calls == 1


async def test_a_second_request_is_served_from_the_cache(tmp_path: Path):
    cache = SbomCache(tmp_path)
    registry = CountingRegistry()

    first = await sbom_for(EXPRESS, cache, registry.client())
    second = await sbom_for(EXPRESS, cache, registry.client())

    assert first == second
    assert registry.calls == 1


async def test_an_existing_entry_is_used_without_asking_the_registry(tmp_path: Path):
    cache = SbomCache(tmp_path)
    cache.put(Sbom(purl="pkg:npm/express@4.18.0", dependencies=()))
    registry = CountingRegistry()

    sbom = await sbom_for(EXPRESS, cache, registry.client())

    assert sbom.dependencies == ()
    assert registry.calls == 0
