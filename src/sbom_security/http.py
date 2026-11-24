"""Ask a service again when it could not answer the first time.

A report is built from many small requests to public services, so one dropped
connection should not cost all of it. A request whose connection fails, or that meets a
server briefly unable to answer, is repeated a few times with growing pauses. Anything
else is an answer, errors included, and is left to the caller. So is a request that
timed out: it has been waited for already.
"""

import asyncio
from typing import Any

import httpx

# How long to wait before each repetition, in seconds.
PAUSES = (0.5, 2.0, 5.0)

# Too many requests, and the gateway errors a restart or an overload gives.
UNAVAILABLE = (429, 502, 503, 504)


class Client(httpx.AsyncClient):
    """An HTTP client for reading from public services, which repeats failed requests.

    Every request is repeated alike, so it is only for requests that change nothing.
    """

    async def send(self, request: httpx.Request, **options: Any) -> httpx.Response:
        for pause in PAUSES:
            try:
                response = await super().send(request, **options)
                if response.status_code not in UNAVAILABLE:
                    return response
            except (httpx.NetworkError, httpx.RemoteProtocolError):
                pass
            await asyncio.sleep(pause)
        return await super().send(request, **options)
