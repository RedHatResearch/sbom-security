"""Fixtures shared by the test modules."""

from collections.abc import Sequence
from pathlib import Path

import httpx
import pytest

from sbom_security.cache import ExpiringCache
from sbom_security.endoflife import EndOfLifeClient
from sbom_security.image import ScanFailed, SyftScanner, parse_reference

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

IMAGES = Path(__file__).parent / "data" / "images"

# The recorded test images, by the repository each comes from. See data/images.
RECORDED_IMAGES = {
    "registry.access.redhat.com/ubi9/ubi-minimal": "ubi-minimal.syft.json",
    "docker.io/library/python": "python-3.12-slim.syft.json",
    "docker.io/library/node": "node-22-alpine.syft.json",
    "docker.io/bkimminich/juice-shop": "juice-shop.syft.json",
}


def serve_express_lifecycle(request: httpx.Request) -> httpx.Response:
    """Answer as endoflife.date would if Express were the only project it covered."""
    if request.url.path.endswith("/identifiers/purl"):
        return httpx.Response(200, json=PACKAGE_URLS)
    if request.url.path.endswith("/products/express"):
        return httpx.Response(200, json={"result": EXPRESS_LIFECYCLE})
    return httpx.Response(404, json={})


async def recorded_syft(arguments: Sequence[str], _timeout: float) -> bytes:
    """Answer as Syft would for a recorded test image, and as a registry would otherwise."""
    reference = parse_reference(arguments[2].removeprefix("registry:"))
    name = RECORDED_IMAGES.get(f"{reference.registry}/{reference.repository}")
    if name is None:
        raise ScanFailed(f"MANIFEST_UNKNOWN: {reference} is not a recorded test image")
    return (IMAGES / name).read_bytes()


@pytest.fixture(name="support_source")
def fixture_support_source(tmp_path: Path) -> EndOfLifeClient:
    """A support source that never reaches the network and knows only Express."""
    return EndOfLifeClient(
        cache=ExpiringCache(tmp_path / "endoflife"),
        transport=httpx.MockTransport(serve_express_lifecycle),
    )


@pytest.fixture(name="image_scanner")
def fixture_image_scanner() -> SyftScanner:
    """An image scanner that answers from recorded Syft output, without the network."""
    return SyftScanner(run=recorded_syft)
