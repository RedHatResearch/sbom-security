"""Tests for delivering reports to the addresses callers give."""

import socket

import httpx
import pytest

from sbom_security.callback import (
    CallbackRefused,
    CallbackSender,
    hosts_from_environment,
    is_public,
)

PUBLIC = "93.184.216.34"


def leading_to(*addresses: str):
    """Resolve every name to the given addresses."""

    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        return addresses

    return resolve


async def unknown_name(_host: str, _port: int) -> tuple[str, ...]:
    raise socket.gaierror("no such name")


class Receiver:
    """Records the requests that reach it."""

    def __init__(self, response: httpx.Response | None = None):
        self.response = response or httpx.Response(200)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


def sender(receiver: Receiver, *addresses: str, hosts: tuple[str, ...] = ()) -> CallbackSender:
    return CallbackSender(
        hosts=hosts,
        resolve=leading_to(*addresses),
        transport=httpx.MockTransport(receiver),
    )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.18.0.2",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.1.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.5",
    ],
)
async def test_refuses_a_host_that_leads_inside(address):
    assert not is_public(address)
    with pytest.raises(CallbackRefused, match="public internet"):
        await CallbackSender(resolve=leading_to(address)).check("https://example.test/")


@pytest.mark.parametrize("address", [PUBLIC, "2606:2800:21f:cb07:6820:80da:af6b:8b2c"])
async def test_accepts_a_host_on_the_public_internet(address):
    await CallbackSender(resolve=leading_to(address)).check("https://example.test/done")


async def test_refuses_a_host_that_leads_both_outside_and_inside():
    with pytest.raises(CallbackRefused):
        await CallbackSender(resolve=leading_to(PUBLIC, "10.0.0.5")).check("https://example.test/")


@pytest.mark.parametrize(
    "address", ["http://127.0.0.1/", "http://2130706433/", "http://[::1]:6379/"]
)
async def test_refuses_an_address_written_as_numbers(address):
    # Resolved by the system, which needs no network for an address that is a number.
    with pytest.raises(CallbackRefused):
        await CallbackSender().check(address)


async def test_a_name_that_does_not_exist_is_refused_like_one_that_leads_inside():
    # Telling the two apart would let a caller ask which names exist inside.
    with pytest.raises(CallbackRefused) as unknown:
        await CallbackSender(resolve=unknown_name).check("https://redis/")
    with pytest.raises(CallbackRefused) as inside:
        await CallbackSender(resolve=leading_to("172.18.0.2")).check("https://redis/")

    assert str(unknown.value) == str(inside.value)


@pytest.mark.parametrize(
    "address",
    [
        "ftp://example.test/",
        "file:///etc/passwd",
        "example.test/done",
        "https://",
        "http://example.test:port/",
    ],
)
async def test_refuses_what_is_not_a_web_address(address):
    with pytest.raises(CallbackRefused):
        await CallbackSender(resolve=leading_to(PUBLIC)).check(address)


async def test_accepts_an_allowed_host_wherever_it_leads():
    receiver = Receiver()
    callbacks = sender(receiver, "10.0.0.5", hosts=("dashboard.internal",))

    await callbacks.send("http://Dashboard.internal:8080/done", {"summary": 1})

    assert str(receiver.requests[0].url) == "http://dashboard.internal:8080/done"


async def test_connects_to_the_address_that_was_checked():
    receiver = Receiver()

    await sender(receiver, PUBLIC).send("https://example.test:8443/done?id=1", {"summary": 1})

    [request] = receiver.requests
    assert str(request.url) == f"https://{PUBLIC}:8443/done?id=1"
    assert request.headers["Host"] == "example.test:8443"
    assert request.extensions["sni_hostname"] == "example.test"


async def test_connects_to_an_ipv6_address():
    receiver = Receiver()

    await sender(receiver, "2606:2800::1").send("https://example.test/done", {})

    assert receiver.requests[0].url.host == "2606:2800::1"
    assert receiver.requests[0].headers["Host"] == "example.test"


async def test_delivers_nothing_to_a_name_that_has_since_been_pointed_inside():
    receiver = Receiver()

    await sender(receiver, "169.254.169.254").send("https://example.test/done", {})

    assert receiver.requests == []


async def test_does_not_follow_a_redirect():
    receiver = Receiver(httpx.Response(302, headers={"Location": "http://10.0.0.5/"}))

    await sender(receiver, PUBLIC).send("https://example.test/done", {})

    assert len(receiver.requests) == 1


def test_reads_the_allowed_hosts_from_the_environment(monkeypatch):
    monkeypatch.setenv("SBOM_CALLBACK_HOSTS", " Dashboard.internal, localhost ,")

    assert hosts_from_environment() == ("dashboard.internal", "localhost")


def test_allows_no_hosts_unless_configured(monkeypatch):
    monkeypatch.delenv("SBOM_CALLBACK_HOSTS", raising=False)

    assert hosts_from_environment() == ()
