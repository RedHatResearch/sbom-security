"""Tests for reading npm manifests."""

from sbom_security.manifest import parse_package_json, project_name
from sbom_security.models import Requirement


def test_reads_declared_dependencies():
    manifest = {"dependencies": {"express": "^4.18.0", "cookie": "0.5.0"}}

    assert parse_package_json(manifest) == (
        Requirement("express", "^4.18.0"),
        Requirement("cookie", "0.5.0"),
    )


def test_includes_development_dependencies():
    # They are installed too, and can carry vulnerabilities of their own.
    manifest = {
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }

    names = {item.name for item in parse_package_json(manifest)}

    assert names == {"express", "jest"}


def test_a_package_declared_twice_is_taken_once():
    manifest = {
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"express": "^4.0.0"},
    }

    assert parse_package_json(manifest) == (Requirement("express", "^4.18.0"),)


def test_ignores_entries_that_are_not_ranges():
    manifest = {"dependencies": {"express": "^4.18.0", "broken": {"nested": "object"}}}

    assert parse_package_json(manifest) == (Requirement("express", "^4.18.0"),)


def test_a_manifest_without_dependencies_yields_nothing():
    assert parse_package_json({"name": "empty"}) == ()


def test_reads_the_project_name():
    assert project_name({"name": "example-project"}) == "example-project"


def test_falls_back_when_the_project_is_unnamed():
    assert project_name({}) == "unnamed project"
