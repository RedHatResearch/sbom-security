"""Tests for Package URL normalization."""

from packageurl import PackageURL

from sbom_security.models import PackageRef
from sbom_security.purl import to_dependencies, to_purl


def test_builds_a_purl_for_a_plain_package():
    assert to_purl(PackageRef("express", "4.18.0")) == "pkg:npm/express@4.18.0"


def test_carries_an_npm_scope_as_the_namespace():
    purl = PackageURL.from_string(to_purl(PackageRef("@babel/core", "7.20.12")))

    assert purl.type == "npm"
    assert purl.namespace == "@babel"
    assert purl.name == "core"
    assert purl.version == "7.20.12"


def test_dependency_keeps_the_original_name_alongside_the_purl():
    dependency = to_dependencies([PackageRef("@babel/core", "7.20.12")])[0]

    # The report shows the name a developer recognizes; the purl is for matching.
    assert dependency.name == "@babel/core"
    assert dependency.version == "7.20.12"
    assert dependency.purl.startswith("pkg:npm/")


def test_converts_every_reference():
    dependencies = to_dependencies(
        [PackageRef("express", "4.18.0"), PackageRef("accepts", "1.3.8")]
    )

    assert [dependency.purl for dependency in dependencies] == [
        "pkg:npm/express@4.18.0",
        "pkg:npm/accepts@1.3.8",
    ]
