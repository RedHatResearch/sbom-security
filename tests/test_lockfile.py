"""Tests for reading npm lockfiles."""

from pathlib import Path

from sbom_security.lockfile import parse_package_lock, parse_package_lock_data
from sbom_security.models import PackageRef

FIXTURE = Path(__file__).parent / "data" / "package-lock.json"


def test_reads_every_pinned_dependency():
    refs = parse_package_lock(FIXTURE)

    assert set(refs) == {
        PackageRef("@babel/core", "7.20.12"),
        PackageRef("accepts", "1.3.8"),
        PackageRef("express", "4.18.0"),
        PackageRef("debug", "2.6.9"),
        PackageRef("jest", "29.3.1"),
    }


def test_skips_the_root_project_and_workspace_links():
    names = {ref.name for ref in parse_package_lock(FIXTURE)}

    assert "example-project" not in names
    assert "workspace-link" not in names


def test_keeps_scoped_names_intact():
    refs = parse_package_lock(FIXTURE)

    assert PackageRef("@babel/core", "7.20.12") in refs


def test_reads_nested_dependencies():
    # debug is installed under express, not at the top level.
    refs = parse_package_lock(FIXTURE)

    assert PackageRef("debug", "2.6.9") in refs


def test_reports_each_name_and_version_once():
    data = {
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/left/node_modules/shared": {"version": "1.0.0"},
            "node_modules/right/node_modules/shared": {"version": "1.0.0"},
        }
    }

    assert parse_package_lock_data(data) == (PackageRef("shared", "1.0.0"),)


def test_keeps_distinct_versions_of_the_same_package():
    data = {
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/shared": {"version": "1.0.0"},
            "node_modules/other/node_modules/shared": {"version": "2.0.0"},
        }
    }

    assert parse_package_lock_data(data) == (
        PackageRef("shared", "1.0.0"),
        PackageRef("shared", "2.0.0"),
    )


def test_supports_the_version_1_layout():
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.18.0",
                "dependencies": {"debug": {"version": "2.6.9"}},
            }
        },
    }

    assert parse_package_lock_data(data) == (
        PackageRef("express", "4.18.0"),
        PackageRef("debug", "2.6.9"),
    )
