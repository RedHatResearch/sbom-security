"""Tests for finding the packages inside a container image.

Syft's output for real public images is recorded under ``data/images``, so these
tests exercise real image contents without Syft, a registry or the network.
"""

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from sbom_security.image import (
    DEFAULT_REGISTRIES,
    InvalidReference,
    RegistryNotAllowed,
    ScanFailed,
    ScanTimedOut,
    SyftScanner,
    assess,
    parse_reference,
    registries_from_environment,
    run_syft,
)

IMAGES = Path(__file__).parent / "data" / "images"
DIGEST = "sha256:" + "a" * 64


def recorded(name: str) -> dict[str, Any]:
    return json.loads((IMAGES / name).read_text(encoding="utf-8"))


class RecordedSyft:
    """Answers as Syft would for one recorded image, and records how it was called."""

    def __init__(self, name: str):
        self.name = name
        self.calls: list[list[str]] = []

    async def __call__(self, arguments: Sequence[str], _timeout: float) -> bytes:
        self.calls.append(list(arguments))
        return (IMAGES / self.name).read_bytes()


def test_an_official_image_is_spelled_out_in_full():
    assert str(parse_reference("python:3.12-slim")) == "docker.io/library/python:3.12-slim"


def test_an_image_without_a_tag_means_latest():
    assert (
        str(parse_reference("bkimminich/juice-shop"))
        == "docker.io/bkimminich/juice-shop:latest"
    )


def test_another_registry_is_kept():
    assert (
        str(parse_reference("registry.access.redhat.com/ubi9/ubi-minimal"))
        == "registry.access.redhat.com/ubi9/ubi-minimal:latest"
    )


def test_a_digest_pins_the_image_without_a_tag():
    assert str(parse_reference(f"python@{DIGEST}")) == f"docker.io/library/python@{DIGEST}"


def test_docker_hubs_other_names_are_one_registry():
    assert parse_reference("index.docker.io/library/node:22").registry == "docker.io"


@pytest.mark.parametrize(
    "text",
    [
        "dir:/etc",  # Syft would read this service's own disk
        "file:/etc/passwd",
        "--output=/tmp/x",
        "Python:3.12",  # repositories are lower case
        "python:",
        "python@sha256:abc",
        "",
        "two words",
    ],
)
def test_refuses_anything_that_is_not_an_image_reference(text: str):
    with pytest.raises(InvalidReference):
        parse_reference(text)


def test_refuses_a_registry_that_is_not_on_the_list():
    # Otherwise a caller could make this service connect into its own network.
    with pytest.raises(RegistryNotAllowed):
        SyftScanner().check("10.0.0.5:5000/internal/thing")


def test_the_list_of_registries_can_be_replaced():
    scanner = SyftScanner(registries=("registry.example.com",))

    assert scanner.check("registry.example.com/team/app:1.0").registry == (
        "registry.example.com"
    )
    with pytest.raises(RegistryNotAllowed):
        scanner.check("python:3.12-slim")


def test_the_registries_come_from_the_environment_when_set(monkeypatch):
    monkeypatch.setenv("SBOM_IMAGE_REGISTRIES", "Registry.Example.com, quay.io")

    assert registries_from_environment() == ("registry.example.com", "quay.io")


def test_the_default_registries_apply_otherwise(monkeypatch):
    monkeypatch.delenv("SBOM_IMAGE_REGISTRIES", raising=False)

    assert registries_from_environment() == DEFAULT_REGISTRIES


async def test_syft_is_asked_for_a_registry_image_and_nothing_else():
    syft = RecordedSyft("node-22-alpine.syft.json")

    await SyftScanner(run=syft).inventory("node:22-alpine")

    assert syft.calls == [
        ["syft", "-q", "registry:docker.io/library/node:22-alpine", "-o", "syft-json"]
    ]


async def test_the_reference_is_pinned_to_the_digest_the_registry_reported():
    scanner = SyftScanner(run=RecordedSyft("python-3.12-slim.syft.json"))

    inventory = await scanner.inventory("python:3.12-slim")

    assert inventory.reference == (
        "docker.io/library/python:3.12-slim"
        "@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f"
    )


async def test_a_digest_the_caller_gave_is_kept():
    scanner = SyftScanner(run=RecordedSyft("python-3.12-slim.syft.json"))

    inventory = await scanner.inventory(f"python@{DIGEST}")

    assert inventory.reference == f"docker.io/library/python@{DIGEST}"


async def test_a_package_installed_in_several_places_is_listed_once():
    found = recorded("juice-shop.syft.json")["artifacts"]
    scanner = SyftScanner(run=RecordedSyft("juice-shop.syft.json"))

    inventory = await scanner.inventory("bkimminich/juice-shop")

    # npm nests copies: the recording holds this one six times over.
    assert sum(item["purl"] == "pkg:npm/ansi-regex@5.0.1" for item in found) == 6
    assert inventory.packages.count("pkg:npm/ansi-regex@5.0.1") == 1
    assert len(inventory.packages) == len(set(inventory.packages))


async def test_entries_without_a_package_url_are_left_out():
    found = recorded("python-3.12-slim.syft.json")["artifacts"]
    scanner = SyftScanner(run=RecordedSyft("python-3.12-slim.syft.json"))

    inventory = await scanner.inventory("python:3.12-slim")

    assert any(not item["purl"] for item in found)
    assert len(inventory.packages) == sum(bool(item["purl"]) for item in found)


async def test_output_that_is_not_json_is_a_failed_scan():
    async def garbled(_arguments: Sequence[str], _timeout: float) -> bytes:
        return b"not json"

    with pytest.raises(ScanFailed):
        await SyftScanner(run=garbled).inventory("node:22-alpine")


def test_npm_and_python_packages_are_assessed():
    assessed, held_back = assess(["pkg:npm/%40isaacs/cliui@8.0.2", "pkg:pypi/pip@25.0.1"])

    assert [(d.name, d.version, d.ecosystem) for d in assessed] == [
        ("@isaacs/cliui", "8.0.2", "npm"),
        ("pip", "25.0.1", "pypi"),
    ]
    assert held_back == ()


def test_operating_system_packages_and_binaries_are_held_back():
    found = (
        "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64&distro=rhel-9.8",
        "pkg:deb/debian/apt@3.0.3?arch=amd64&distro=debian-13.7",
        "pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.24.2",
        "pkg:generic/node@22.23.3",
    )

    assessed, held_back = assess(found)

    assert assessed == ()
    assert held_back == found


async def test_nothing_in_an_rhel_image_is_assessed_yet():
    scanner = SyftScanner(run=RecordedSyft("ubi-minimal.syft.json"))

    assessed, held_back = assess((await scanner.inventory("ubi9/ubi-minimal")).packages)

    assert assessed == ()
    assert len(held_back) == 109
    assert all(purl.startswith("pkg:rpm/redhat/") for purl in held_back)


async def test_an_application_image_is_mostly_assessed():
    scanner = SyftScanner(run=RecordedSyft("juice-shop.syft.json"))

    assessed, held_back = assess((await scanner.inventory("bkimminich/juice-shop")).packages)

    assert {dependency.ecosystem for dependency in assessed} == {"npm"}
    assert any(purl.startswith("pkg:deb/") for purl in held_back)


async def test_running_returns_what_the_program_writes():
    output = await run_syft([sys.executable, "-c", "print('{}')"], timeout=10)

    assert json.loads(output) == {}


async def test_a_failure_is_reported_with_the_programs_last_word():
    script = (
        "import sys; sys.stderr.write('pulling\\nMANIFEST_UNKNOWN: manifest unknown\\n');"
        " sys.exit(1)"
    )

    with pytest.raises(ScanFailed, match="MANIFEST_UNKNOWN"):
        await run_syft([sys.executable, "-c", script], timeout=10)


async def test_a_scan_that_runs_too_long_is_stopped():
    with pytest.raises(ScanTimedOut):
        await run_syft([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)


async def test_a_missing_program_is_reported_plainly():
    with pytest.raises(ScanFailed, match="Could not run"):
        await run_syft(["no-such-syft-anywhere"], timeout=10)


def test_a_package_found_without_a_version_is_not_assessed():
    # Syft reports package.json files that carry no version, such as test fixtures
    # inside node_modules. Without a version nothing can be matched against them.
    assessed, held_back = assess(["pkg:npm/baz"])

    assert assessed == ()
    assert held_back == ("pkg:npm/baz",)
