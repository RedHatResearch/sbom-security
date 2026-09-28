"""Tests for resolving npm version ranges against the registry."""

import httpx

from sbom_security.models import PackageRef, Requirement
from sbom_security.npm import NpmRegistry

PUBLISHED = {
    "express": ["4.17.0", "4.18.0", "4.18.2", "4.19.2", "5.0.0"],
    "cookie": ["0.4.0", "0.5.0"],
    "@babel/core": ["7.20.0", "7.20.12"],
}


def registry_serving(versions: dict[str, list[str]]) -> NpmRegistry:
    def handle(request: httpx.Request) -> httpx.Response:
        name = request.url.path.lstrip("/")
        # The registry escapes a scope, so undo that to look the package up.
        name = name.replace("%2F", "/").replace("%2f", "/")
        if name not in versions:
            return httpx.Response(404, json={})
        return httpx.Response(
            200, json={"versions": {version: {} for version in versions[name]}}
        )

    return NpmRegistry(transport=httpx.MockTransport(handle))


def test_escapes_a_scoped_name_into_one_path_segment():
    url = NpmRegistry().package_url("@babel/core")

    assert url == "https://registry.npmjs.org/%40babel%2Fcore"


async def test_picks_the_highest_version_satisfying_a_caret_range():
    resolved, unresolved = await registry_serving(PUBLISHED).resolve(
        [Requirement("express", "^4.18.0")]
    )

    # 5.0.0 is published but crosses the major boundary, so it does not apply.
    assert resolved == (PackageRef("express", "4.19.2"),)
    assert unresolved == ()


async def test_an_exact_range_resolves_to_that_version():
    resolved, _ = await registry_serving(PUBLISHED).resolve(
        [Requirement("cookie", "0.5.0")]
    )

    assert resolved == (PackageRef("cookie", "0.5.0"),)


async def test_resolves_a_scoped_package():
    resolved, _ = await registry_serving(PUBLISHED).resolve(
        [Requirement("@babel/core", "^7.20.0")]
    )

    assert resolved == (PackageRef("@babel/core", "7.20.12"),)


async def test_resolves_several_requirements_at_once():
    resolved, _ = await registry_serving(PUBLISHED).resolve(
        [Requirement("express", "^4.18.0"), Requirement("cookie", "^0.4.0")]
    )

    assert set(resolved) == {
        PackageRef("express", "4.19.2"),
        PackageRef("cookie", "0.4.0"),
    }


async def test_a_caret_below_version_one_stops_at_the_minor():
    # npm treats a leading zero as unstable: ^1.2.3 allows anything below 2.0.0, but
    # ^0.4.0 allows only below 0.5.0, because a minor bump there can still break the
    # API. Getting this wrong would silently resolve to a version the project never
    # accepted, and report the vulnerabilities of the wrong one.
    resolved, _ = await registry_serving(PUBLISHED).resolve(
        [Requirement("cookie", "^0.4.0")]
    )

    assert resolved == (PackageRef("cookie", "0.4.0"),)


async def test_records_a_package_the_registry_does_not_know():
    resolved, unresolved = await registry_serving(PUBLISHED).resolve(
        [Requirement("nope", "^1.0.0")]
    )

    assert resolved == ()
    assert unresolved == ("nope@^1.0.0",)


async def test_records_a_requirement_that_is_not_a_version_range():
    # Local paths, git URLs and aliases appear in real manifests and cannot be
    # resolved from the registry.
    resolved, unresolved = await registry_serving(PUBLISHED).resolve(
        [Requirement("express", "file:../local-copy")]
    )

    assert resolved == ()
    assert unresolved == ("express@file:../local-copy",)


async def test_one_unresolvable_requirement_does_not_lose_the_others():
    resolved, unresolved = await registry_serving(PUBLISHED).resolve(
        [Requirement("nope", "^1.0.0"), Requirement("express", "^4.18.0")]
    )

    assert resolved == (PackageRef("express", "4.19.2"),)
    assert unresolved == ("nope@^1.0.0",)


async def test_nothing_to_resolve_asks_nothing():
    assert await registry_serving(PUBLISHED).resolve([]) == ((), ())
