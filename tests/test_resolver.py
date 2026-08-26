"""Tests for building SBOMs through the cache, and for walking the dependency tree."""

from pathlib import Path
from typing import Any

import httpx
import pytest

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef
from sbom_security.registry import DepsDevClient, PackageNotFound
from sbom_security.resolver import resolve_tree, sbom_for

EXPRESS = PackageRef("express", "4.18.0")


def graph(name: str, version: str, dependencies: list[tuple[str, str]]) -> dict[str, Any]:
    """Build a deps.dev style response for one package version."""
    nodes: list[dict[str, Any]] = [
        {"versionKey": {"system": "NPM", "name": name, "version": version},
         "relation": "SELF"}
    ]
    nodes += [
        {"versionKey": {"system": "NPM", "name": dep_name, "version": dep_version},
         "relation": "DIRECT"}
        for dep_name, dep_version in dependencies
    ]
    return {"nodes": nodes}


class FakeRegistry:
    """Serves canned dependency graphs and counts what was asked for."""

    def __init__(self, graphs: dict[str, dict[str, Any]]):
        self.graphs = graphs
        self.requested: list[str] = []

    def client(self) -> DepsDevClient:
        def handle(request: httpx.Request) -> httpx.Response:
            # ".../packages/<name>/versions/<version>:dependencies"
            parts = str(request.url).split("/packages/")[1]
            name, rest = parts.split("/versions/")
            version = rest.removesuffix(":dependencies")
            key = f"{name}@{version}"
            self.requested.append(key)
            if key not in self.graphs:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.graphs[key])

        return DepsDevClient(transport=httpx.MockTransport(handle))


# express -> accepts -> mime-types -> mime
CHAIN = FakeRegistry(
    {
        "express@4.18.0": graph("express", "4.18.0", [("accepts", "1.3.8")]),
        "accepts@1.3.8": graph("accepts", "1.3.8", [("mime-types", "2.1.35")]),
        "mime-types@2.1.35": graph("mime-types", "2.1.35", [("mime", "1.6.0")]),
        "mime@1.6.0": graph("mime", "1.6.0", []),
    }
)


def names(resolution) -> set[str]:
    return {ref.name for ref in resolution.packages}


async def test_builds_and_stores_an_sbom_that_is_not_cached(tmp_path: Path):
    cache = SbomCache(tmp_path)
    registry = FakeRegistry({"express@4.18.0": graph("express", "4.18.0", [("accepts", "1.3.8")])})

    sbom = await sbom_for(EXPRESS, cache, registry.client())

    assert sbom.dependencies == (PackageRef("accepts", "1.3.8"),)
    assert cache.has("pkg:npm/express@4.18.0")
    assert registry.requested == ["express@4.18.0"]


async def test_a_second_request_is_served_from_the_cache(tmp_path: Path):
    cache = SbomCache(tmp_path)
    registry = FakeRegistry({"express@4.18.0": graph("express", "4.18.0", [])})

    first = await sbom_for(EXPRESS, cache, registry.client())
    second = await sbom_for(EXPRESS, cache, registry.client())

    assert first == second
    assert registry.requested == ["express@4.18.0"]


async def test_the_walk_includes_the_root_itself(tmp_path: Path):
    resolution = await resolve_tree(EXPRESS, SbomCache(tmp_path), CHAIN.client(), depth=1)

    assert "express" in names(resolution)


async def test_depth_one_reaches_the_direct_dependencies(tmp_path: Path):
    resolution = await resolve_tree(EXPRESS, SbomCache(tmp_path), CHAIN.client(), depth=1)

    assert names(resolution) == {"express", "accepts"}


async def test_depth_two_reaches_one_level_further(tmp_path: Path):
    resolution = await resolve_tree(EXPRESS, SbomCache(tmp_path), CHAIN.client(), depth=2)

    assert names(resolution) == {"express", "accepts", "mime-types"}


async def test_a_walk_stopped_by_the_depth_limit_says_so(tmp_path: Path):
    resolution = await resolve_tree(EXPRESS, SbomCache(tmp_path), CHAIN.client(), depth=2)

    assert resolution.truncated is True


async def test_a_walk_that_reaches_the_leaves_is_not_truncated(tmp_path: Path):
    resolution = await resolve_tree(EXPRESS, SbomCache(tmp_path), CHAIN.client(), depth=9)

    assert resolution.truncated is False
    assert names(resolution) == {"express", "accepts", "mime-types", "mime"}


async def test_a_cycle_terminates(tmp_path: Path):
    # a depends on b, and b depends back on a.
    registry = FakeRegistry(
        {
            "a@1.0.0": graph("a", "1.0.0", [("b", "1.0.0")]),
            "b@1.0.0": graph("b", "1.0.0", [("a", "1.0.0")]),
        }
    )

    resolution = await resolve_tree(
        PackageRef("a", "1.0.0"), SbomCache(tmp_path), registry.client(), depth=9
    )

    assert names(resolution) == {"a", "b"}
    assert resolution.truncated is False


async def test_a_package_reached_twice_is_expanded_once(tmp_path: Path):
    # Both branches depend on the same version of shared.
    registry = FakeRegistry(
        {
            "root@1.0.0": graph("root", "1.0.0", [("left", "1.0.0"), ("right", "1.0.0")]),
            "left@1.0.0": graph("left", "1.0.0", [("shared", "1.0.0")]),
            "right@1.0.0": graph("right", "1.0.0", [("shared", "1.0.0")]),
            "shared@1.0.0": graph("shared", "1.0.0", []),
        }
    )

    await resolve_tree(
        PackageRef("root", "1.0.0"), SbomCache(tmp_path), registry.client(), depth=9
    )

    assert registry.requested.count("shared@1.0.0") == 1


async def test_an_unknown_root_is_an_error(tmp_path: Path):
    # Being asked about a package that does not exist is a mistake worth reporting,
    # unlike a single unknown package somewhere down the tree.
    registry = FakeRegistry({})

    with pytest.raises(PackageNotFound):
        await resolve_tree(
            PackageRef("nope", "9.9.9"), SbomCache(tmp_path), registry.client(), depth=3
        )


async def test_an_unknown_package_is_recorded_and_the_walk_continues(tmp_path: Path):
    registry = FakeRegistry(
        {"root@1.0.0": graph("root", "1.0.0", [("missing", "9.9.9"), ("ms", "2.1.3")]),
         "ms@2.1.3": graph("ms", "2.1.3", [])}
    )

    resolution = await resolve_tree(
        PackageRef("root", "1.0.0"), SbomCache(tmp_path), registry.client(), depth=9
    )

    assert names(resolution) == {"root", "missing", "ms"}
    assert resolution.unresolved == ("pkg:npm/missing@9.9.9",)


async def test_the_cache_is_shared_across_walks(tmp_path: Path):
    cache = SbomCache(tmp_path)

    await resolve_tree(EXPRESS, cache, CHAIN.client(), depth=9)
    before = len(CHAIN.requested)
    await resolve_tree(EXPRESS, cache, CHAIN.client(), depth=9)

    assert len(CHAIN.requested) == before
