"""Tests for reading dependency files from a public GitHub repository."""

import httpx
import pytest

from sbom_security.github import FileNotFound, GitHubSource, LockfileNotFound

LOCKFILE = {"name": "example", "lockfileVersion": 3, "packages": {}}
MANIFEST = {"name": "example", "dependencies": {"express": "^4.18.0"}}


def source_serving(files: dict[str, dict]) -> GitHubSource:
    """A source that has only the named files."""

    def handle(request: httpx.Request) -> httpx.Response:
        filename = request.url.path.rsplit("/", 1)[-1]
        if filename not in files:
            return httpx.Response(404, text="404: Not Found")
        return httpx.Response(200, json=files[filename])

    return GitHubSource(transport=httpx.MockTransport(handle))


def test_builds_the_raw_url_for_the_default_branch():
    url = GitHubSource().lockfile_url("OWASP", "NodeGoat")

    # HEAD resolves to whichever branch the repository treats as default.
    assert url == "https://raw.githubusercontent.com/OWASP/NodeGoat/HEAD/package-lock.json"


def test_builds_the_raw_url_for_an_explicit_ref():
    url = GitHubSource().lockfile_url("OWASP", "NodeGoat", "master")

    assert url.endswith("/OWASP/NodeGoat/master/package-lock.json")


async def test_returns_the_parsed_lockfile():
    source = source_serving({"package-lock.json": LOCKFILE})

    assert await source.fetch_lockfile("OWASP", "NodeGoat") == LOCKFILE


async def test_returns_the_parsed_manifest():
    source = source_serving({"package.json": MANIFEST})

    assert await source.fetch_manifest("expressjs", "express") == MANIFEST


async def test_reports_a_missing_lockfile_clearly():
    source = source_serving({"package.json": MANIFEST})

    with pytest.raises(LockfileNotFound, match="package-lock.json"):
        await source.fetch_lockfile("expressjs", "express")


async def test_reports_a_missing_manifest_clearly():
    source = source_serving({})

    with pytest.raises(FileNotFound, match="package.json"):
        await source.fetch_manifest("some", "repo")


async def test_raises_on_other_failures():
    def handle(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={})

    source = GitHubSource(transport=httpx.MockTransport(handle))

    with pytest.raises(httpx.HTTPStatusError):
        await source.fetch_lockfile("OWASP", "NodeGoat")
