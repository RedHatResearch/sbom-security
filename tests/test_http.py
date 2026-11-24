"""Tests for the HTTP client that repeats failed requests."""

import httpx
import pytest

from sbom_security.http import Client
from sbom_security.models import PackageRef
from sbom_security.registry import DepsDevClient


class Flaky:
    """Fails as told for its first requests, and answers the rest."""

    def __init__(self, *failures: Exception | int):
        self.failures = list(failures)
        self.requests = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if not self.failures:
            return httpx.Response(200, json={"nodes": []})
        failure = self.failures.pop(0)
        if isinstance(failure, Exception):
            raise failure
        return httpx.Response(failure)


async def get(service: Flaky) -> httpx.Response:
    async with Client(transport=httpx.MockTransport(service)) as client:
        return await client.get("https://service.test/")


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadError("dropped"),
        httpx.ConnectError("unreachable"),
        httpx.RemoteProtocolError("closed early"),
        429,
        502,
        503,
        504,
    ],
)
async def test_repeats_a_request_that_could_not_be_answered(failure):
    service = Flaky(failure, failure)

    response = await get(service)

    assert response.status_code == 200
    assert service.requests == 3


@pytest.mark.parametrize("status", [400, 404, 500])
async def test_takes_any_other_status_for_an_answer(status):
    service = Flaky(status)

    response = await get(service)

    assert response.status_code == status
    assert service.requests == 1


async def test_gives_up_on_a_connection_that_keeps_failing():
    service = Flaky(*[httpx.ReadError("dropped")] * 9)

    with pytest.raises(httpx.ReadError):
        await get(service)

    assert service.requests == 4


async def test_hands_back_the_last_refusal_of_a_server_that_stays_unavailable():
    service = Flaky(*[503] * 9)

    response = await get(service)

    assert response.status_code == 503
    assert service.requests == 4


async def test_does_not_wait_again_for_a_request_that_timed_out():
    service = Flaky(httpx.ReadTimeout("slow"))

    with pytest.raises(httpx.ReadTimeout):
        await get(service)

    assert service.requests == 1


async def test_a_dropped_connection_does_not_end_a_lookup():
    service = Flaky(httpx.ReadError("dropped"))

    sbom = await DepsDevClient(
        transport=httpx.MockTransport(service)
    ).direct_dependencies(PackageRef("express", "4.18.0"))

    assert sbom.purl == "pkg:npm/express@4.18.0"
