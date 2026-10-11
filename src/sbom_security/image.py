"""Find the packages inside a container image, without running it.

An image does not declare its dependencies the way a lockfile does; they have to be
found in it. Syft does that. It reads an image straight from its registry, without a
container runtime, and lists the packages it finds both in the operating system's
package databases and in language package directories such as node_modules and
site-packages, each with its Package URL.

Syft is only ever handed a reference this module has checked. It can also read local
paths, which a caller must never reach, so every reference is parsed and rebuilt as a
registry reference. It would also connect to whatever host it is named, which would
let a caller make this service reach into its own network, so only registries on an
allowed list are accepted.
"""

import asyncio
import json
import os
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from packageurl import PackageURL

from sbom_security import distribution
from sbom_security.models import NPM, PYPI, Dependency, PackageRef
from sbom_security.purl import to_dependency

DOCKER_HUB = "docker.io"

# Other names for Docker Hub, which Syft itself uses when it reports a digest.
DOCKER_HUB_ALIASES = ("index.docker.io", "registry-1.docker.io")

# Registries that serve public images without credentials. SBOM_IMAGE_REGISTRIES, a
# comma-separated list, replaces this one.
DEFAULT_REGISTRIES = (
    "docker.io",
    "quay.io",
    "ghcr.io",
    "gcr.io",
    "registry.access.redhat.com",
    "public.ecr.aws",
    "mcr.microsoft.com",
    "registry.k8s.io",
)

# An image can be gigabytes, and nothing upstream bounds how long pulling one takes.
SCAN_TIMEOUT = 300.0

# Each scan downloads a whole image to temporary storage, so only a few run at once.
MAX_CONCURRENT_SCANS = 2

# Language package types, matched by Package URL. Distribution packages are matched
# against their distribution's own advisories where ``distribution`` handles it, and
# held back otherwise rather than matched against upstream ones and wrongly reported.
LANGUAGE_TYPES = (NPM, PYPI)

_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_REPOSITORY = re.compile(rf"{_COMPONENT}(?:/{_COMPONENT})*")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")

_SCANS = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


class InvalidReference(ValueError):
    """The text is not an image reference."""


class RegistryNotAllowed(ValueError):
    """The image is on a registry this service may not contact."""


class ScanFailed(RuntimeError):
    """Syft could not read the image."""


class ScanTimedOut(ScanFailed):
    """Reading the image took longer than allowed."""


@dataclass(frozen=True)
class ImageReference:
    """An image reference with nothing left implicit."""

    registry: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    def __str__(self) -> str:
        text = f"{self.registry}/{self.repository}"
        if self.tag:
            text += f":{self.tag}"
        if self.digest:
            text += f"@{self.digest}"
        return text


def parse_reference(text: str) -> ImageReference:
    """Read an image reference the way Docker does, and spell it out in full.

    ``python:3.12-slim`` names ``docker.io/library/python:3.12-slim``: an image with no
    registry is on Docker Hub, an official image there lives under ``library``, and one
    with neither tag nor digest means ``latest``. Spelling it out gives one image one
    name, however it was asked for.

    Anything that is not a reference is refused, including Syft's other kinds of
    source such as ``dir:/etc``, which would read this service's own disk.
    """
    name, at, digest = text.strip().partition("@")
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, path = first.lower(), rest
    else:
        registry, path = DOCKER_HUB, name
    if registry in DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB

    head, _, last = path.rpartition("/")
    last, colon, tag = last.partition(":")
    repository = f"{head}/{last}" if head else last
    if registry == DOCKER_HUB and "/" not in repository:
        repository = f"library/{repository}"

    if not (
        _HOST.fullmatch(registry)
        and _REPOSITORY.fullmatch(repository)
        and (not colon or _TAG.fullmatch(tag))
        and (not at or _DIGEST.fullmatch(digest))
    ):
        raise InvalidReference(f"Not an image reference: {text!r}")

    return ImageReference(
        registry=registry,
        repository=repository,
        tag=tag or (None if at else "latest"),
        digest=digest or None,
    )


def registries_from_environment() -> tuple[str, ...]:
    """Return the registries images may come from, as configured."""
    configured = os.environ.get("SBOM_IMAGE_REGISTRIES", "")
    listed = tuple(
        registry.strip().lower() for registry in configured.split(",") if registry.strip()
    )
    return listed or DEFAULT_REGISTRIES


async def run_syft(arguments: Sequence[str], timeout: float) -> bytes:
    """Run Syft and return what it writes, or say plainly why it could not finish.

    A run that takes too long is killed rather than abandoned, so a slow registry
    cannot leave scans piling up in the background.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )
    except OSError as unavailable:
        raise ScanFailed(
            f"Could not run {arguments[0]}: {unavailable.strerror}"
        ) from unavailable

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise ScanTimedOut(
            f"Reading the image took longer than {timeout:g} seconds"
        ) from None

    if process.returncode != 0:
        lines = stderr.decode(errors="replace").strip().splitlines()
        raise ScanFailed(
            lines[-1] if lines else f"{arguments[0]} exited with {process.returncode}"
        )
    return stdout


Runner = Callable[[Sequence[str], float], Awaitable[bytes]]


@dataclass(frozen=True)
class ImageInventory:
    """What was found in one image.

    ``reference`` names the image exactly as it was read, pinned by digest where the
    registry gave one, since a tag can point at a different image tomorrow.
    ``packages`` holds the Package URL of everything found, each once.
    """

    reference: str
    packages: tuple[str, ...]


@dataclass(frozen=True)
class SyftScanner:
    """Finds the packages in container images by running Syft.

    ``run`` exists so tests can answer as Syft would, without Syft being installed.
    """

    executable: str = "syft"
    registries: tuple[str, ...] = DEFAULT_REGISTRIES
    timeout: float = SCAN_TIMEOUT
    run: Runner = run_syft

    def check(self, text: str) -> ImageReference:
        """Spell out an image reference, and refuse it unless its registry is allowed."""
        reference = parse_reference(text)
        if reference.registry not in self.registries:
            raise RegistryNotAllowed(
                f"Images from {reference.registry} are not accepted here. "
                f"Accepted registries: {', '.join(self.registries)}."
            )
        return reference

    async def inventory(self, text: str) -> ImageInventory:
        """Find every package in an image, read straight from its registry."""
        reference = self.check(text)
        async with _SCANS:
            output = await self.run(
                [self.executable, "-q", f"registry:{reference}", "-o", "syft-json"],
                self.timeout,
            )
        try:
            document = json.loads(output)
        except ValueError as unreadable:
            raise ScanFailed("Syft's output could not be read") from unreadable
        return read_inventory(document, reference)


def read_inventory(document: dict[str, Any], reference: ImageReference) -> ImageInventory:
    """Collect the Package URLs Syft found, each once, and pin the reference.

    A package installed in several places, as npm nests copies, is one package as far
    as its vulnerabilities go. Entries without a Package URL, such as some binaries,
    name nothing that could be looked up and are left out.
    """
    found = dict.fromkeys(
        artifact["purl"]
        for artifact in document.get("artifacts") or []
        if artifact.get("purl")
    )
    return ImageInventory(
        reference=str(_pinned(reference, document)), packages=tuple(found)
    )


def _pinned(reference: ImageReference, document: dict[str, Any]) -> ImageReference:
    """Add the digest the registry reported, unless the caller already gave one."""
    if reference.digest:
        return reference
    metadata = (document.get("source") or {}).get("metadata") or {}
    for repo_digest in metadata.get("repoDigests") or []:
        digest = repo_digest.rpartition("@")[2]
        if _DIGEST.fullmatch(digest):
            return replace(reference, digest=digest)
    return reference


def assess(packages: Sequence[str]) -> tuple[tuple[Dependency, ...], tuple[str, ...]]:
    """Split found packages into those matched against vulnerability data and the rest.

    The rest come back exactly as found, so that a report can list them as not
    assessed rather than leave them out or present them as clean.
    """
    assessed: dict[Dependency, None] = {}
    held_back: list[str] = []
    for purl in packages:
        try:
            parsed = PackageURL.from_string(purl)
        except ValueError:
            held_back.append(purl)
            continue
        if parsed.type in LANGUAGE_TYPES and parsed.version:
            name = f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
            ref = PackageRef(name=name, version=parsed.version, ecosystem=parsed.type)
            assessed[to_dependency(ref)] = None
        elif distribution.ecosystems(parsed):
            # Kept exactly as found: its qualifiers say how to ask about it.
            version = distribution.installed_version(parsed)
            assessed[Dependency(parsed.name, version, purl, parsed.type)] = None
        else:
            held_back.append(purl)
    return tuple(assessed), tuple(held_back)
