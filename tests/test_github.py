"""Tests for reading a lockfile from a public GitHub repository."""

import httpx
import pytest

from sbom_security.github import GitHubSource, LockfileNotFound

LOCKFILE = {"name": "example", "lockfileVersion": 3, "packages": {}}


def source_returning(status: int, payload: dict | None = None) -> GitHubSource:
    def handle(request: httpx.Request) -> httpx.Response:
        handle.path = request.url.path
        return httpx.Response(status, json=payload or {})

    return GitHubSource(transport=httpx.MockTransport(handle))


def test_builds_the_raw_url_for_the_default_branch():
    url = GitHubSource().lockfile_url("OWASP", "NodeGoat")

    # HEAD resolves to whichever branch the repository treats as default.
    assert url == "https://raw.githubusercontent.com/OWASP/NodeGoat/HEAD/package-lock.json"


def test_builds_the_raw_url_for_an_explicit_ref():
    url = GitHubSource().lockfile_url("OWASP", "NodeGoat", "master")

    assert url.endswith("/OWASP/NodeGoat/master/package-lock.json")


def test_returns_the_parsed_lockfile():
    source = source_returning(200, LOCKFILE)

    assert source.fetch_lockfile("OWASP", "NodeGoat") == LOCKFILE


def test_reports_a_missing_lockfile_clearly():
    source = source_returning(404)

    with pytest.raises(LockfileNotFound, match="no package-lock.json"):
        source.fetch_lockfile("expressjs", "express")


def test_raises_on_other_failures():
    source = source_returning(500)

    with pytest.raises(httpx.HTTPStatusError):
        source.fetch_lockfile("OWASP", "NodeGoat")
