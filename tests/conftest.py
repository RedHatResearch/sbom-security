"""Fixtures shared by the test modules."""

from pathlib import Path

import httpx
import pytest

from sbom_security.cache import ExpiringCache
from sbom_security.endoflife import EndOfLifeClient

# Express is the one project this support source knows. Its 4.x line is supported,
# without a separate main period, and its 3.x line reached its end of life in 2015.
EXPRESS_LIFECYCLE = {
    "name": "express",
    "labels": {"eoas": None, "eol": "Security Support"},
    "links": {"html": "https://endoflife.date/express"},
    "releases": [
        {"name": "4", "isEol": False, "eolFrom": None},
        {"name": "3", "isEol": True, "eolFrom": "2015-07-05"},
    ],
}

PACKAGE_URLS = {
    "result": [{"identifier": "pkg:npm/express", "product": {"name": "express"}}]
}


def serve_express_lifecycle(request: httpx.Request) -> httpx.Response:
    """Answer as endoflife.date would if Express were the only project it covered."""
    if request.url.path.endswith("/identifiers/purl"):
        return httpx.Response(200, json=PACKAGE_URLS)
    if request.url.path.endswith("/products/express"):
        return httpx.Response(200, json={"result": EXPRESS_LIFECYCLE})
    return httpx.Response(404, json={})


@pytest.fixture(name="support_source")
def fixture_support_source(tmp_path: Path) -> EndOfLifeClient:
    """A support source that never reaches the network and knows only Express."""
    return EndOfLifeClient(
        cache=ExpiringCache(tmp_path / "endoflife"),
        transport=httpx.MockTransport(serve_express_lifecycle),
    )
