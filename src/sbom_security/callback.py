"""Deliver finished reports to the addresses callers give.

A callback address is chosen by whoever submits the work, but it is this service that
connects to it. Left unchecked, that would let a caller make the service reach whatever
it can reach itself: its own network, the Redis beside it, a cloud provider's metadata.
Only hosts on the public internet are accepted, and hosts listed as allowed.

An address is checked when work is submitted, so that a mistake is reported at once, and
again when the report is delivered, because a name can be pointed elsewhere in between.
The connection then goes to the very address that was checked. Redirects are not
followed, since they would lead to one that was not.
"""

import asyncio
import ipaddress
import os
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_PORTS = {"http": 80, "https": 443}

TIMEOUT = 10.0

Resolver = Callable[[str, int], Awaitable[tuple[str, ...]]]


class CallbackRefused(ValueError):
    """A report must not be delivered to this address."""


async def resolve_host(host: str, port: int) -> tuple[str, ...]:
    """Return the network addresses a host name leads to."""
    found = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    )
    return tuple(dict.fromkeys(str(sockaddr[0]) for *_, sockaddr in found))


def hosts_from_environment() -> tuple[str, ...]:
    """Return the hosts that are accepted wherever they are, as configured."""
    configured = os.environ.get("SBOM_CALLBACK_HOSTS", "")
    return tuple(host.strip().lower() for host in configured.split(",") if host.strip())


def is_public(address: str) -> bool:
    """Say whether a network address is on the public internet.

    An IPv4 address can be written as an IPv6 one, ``::ffff:127.0.0.1``, and is judged
    as what it stands for.
    """
    ip = ipaddress.ip_address(address)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_global and not ip.is_multicast


@dataclass(frozen=True)
class CallbackSender:
    """Posts reports to callback addresses that are safe to connect to.

    ``hosts`` are accepted without being checked. ``resolve`` and ``transport`` exist so
    tests can say where a name leads, and answer there, without network access.
    """

    hosts: tuple[str, ...] = ()
    resolve: Resolver = resolve_host
    transport: httpx.AsyncBaseTransport | None = None

    async def check(self, address: str) -> None:
        """Refuse an address a report must not be posted to, saying why."""
        await self._destination(address)

    async def send(self, address: str, payload: dict[str, Any]) -> None:
        """Post a finished report to an address.

        A caller that cannot be reached must not discard work that has already been
        done, so a failed delivery is passed over and the result stays available to
        collect.
        """
        try:
            url, checked = await self._destination(address)
            headers: dict[str, str] = {}
            extensions: dict[str, Any] = {}
            if checked is not None:
                # Connect to the address that was checked, but speak to the host that
                # was named, whose certificate is the one that has to be right.
                headers["Host"] = url.netloc.decode("ascii")
                extensions["sni_hostname"] = url.raw_host.decode("ascii")
                url = url.copy_with(host=checked)
            # A proxy from the environment would look the name up again by itself.
            async with httpx.AsyncClient(
                timeout=TIMEOUT, transport=self.transport, trust_env=checked is None
            ) as client:
                response = await client.post(
                    url, json=payload, headers=headers, extensions=extensions
                )
                response.raise_for_status()
        except (httpx.HTTPError, CallbackRefused):
            pass

    async def _destination(self, address: str) -> tuple[httpx.URL, str | None]:
        """Return an address, and the network address to reach it at if it was checked."""
        try:
            url = httpx.URL(address)
        except httpx.InvalidURL as invalid:
            raise CallbackRefused(f"Not a callback address: {address!r}") from invalid
        if url.scheme not in DEFAULT_PORTS or not url.host:
            raise CallbackRefused("A callback address begins with http:// or https://")
        if url.host.lower() in self.hosts:
            return url, None

        try:
            found = await self.resolve(url.host, url.port or DEFAULT_PORTS[url.scheme])
        except (OSError, UnicodeError):
            found = ()
        # The same answer whether a name does not exist or leads inside, so that asking
        # reveals nothing about the network the service runs in.
        if not found or not all(is_public(one) for one in found):
            raise CallbackRefused(f"{url.host} is not a host on the public internet")
        return url, found[0]
