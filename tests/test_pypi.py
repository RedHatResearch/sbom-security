"""Tests for resolving Python specifiers against the package index."""

import httpx

from sbom_security.models import PYPI, PackageRef, Requirement
from sbom_security.pypi import PyPiIndex

RELEASED = {
    "django": ["4.1.0", "4.2.0", "4.2.7", "5.0.0"],
    "requests": ["2.27.0", "2.28.0", "2.31.0"],
    "flask": ["2.3.0", "3.0.0", "3.1.0rc1"],
}


def index_serving(releases: dict[str, list[str]]) -> PyPiIndex:
    def handle(request: httpx.Request) -> httpx.Response:
        name = request.url.path.split("/")[2]
        if name not in releases:
            return httpx.Response(404, json={})
        return httpx.Response(
            200, json={"releases": {version: [] for version in releases[name]}}
        )

    return PyPiIndex(transport=httpx.MockTransport(handle))


def requirement(name: str, specifier: str) -> Requirement:
    return Requirement(name, specifier, PYPI)


def test_builds_the_index_url():
    assert PyPiIndex().package_url("django") == "https://pypi.org/pypi/django/json"


async def test_a_pin_resolves_to_that_version():
    resolved, unresolved = await index_serving(RELEASED).resolve(
        [requirement("django", "==4.2.0")]
    )

    assert resolved == (PackageRef("django", "4.2.0", PYPI),)
    assert unresolved == ()


async def test_a_range_resolves_to_the_highest_match():
    resolved, _ = await index_serving(RELEASED).resolve(
        [requirement("django", ">=4.0,<5.0")]
    )

    # 5.0.0 is released but excluded by the upper bound.
    assert resolved == (PackageRef("django", "4.2.7", PYPI),)


async def test_no_specifier_means_the_latest_release():
    resolved, _ = await index_serving(RELEASED).resolve([requirement("requests", "")])

    assert resolved == (PackageRef("requests", "2.31.0", PYPI),)


async def test_pre_releases_are_left_out_unless_asked_for():
    # pip behaves the same way: a project asking for >=2.0 does not expect an rc.
    resolved, _ = await index_serving(RELEASED).resolve([requirement("flask", ">=2.0")])

    assert resolved == (PackageRef("flask", "3.0.0", PYPI),)


async def test_records_a_package_the_index_does_not_know():
    resolved, unresolved = await index_serving(RELEASED).resolve(
        [requirement("nope", ">=1.0")]
    )

    assert resolved == ()
    assert unresolved == ("nope>=1.0",)


async def test_records_a_specifier_nothing_satisfies():
    resolved, unresolved = await index_serving(RELEASED).resolve(
        [requirement("django", ">=99.0")]
    )

    assert resolved == ()
    assert unresolved == ("django>=99.0",)


async def test_one_unresolvable_requirement_does_not_lose_the_others():
    resolved, unresolved = await index_serving(RELEASED).resolve(
        [requirement("nope", ">=1.0"), requirement("django", "==4.2.0")]
    )

    assert resolved == (PackageRef("django", "4.2.0", PYPI),)
    assert unresolved == ("nope>=1.0",)


async def test_nothing_to_resolve_asks_nothing():
    assert await index_serving(RELEASED).resolve([]) == ((), ())
