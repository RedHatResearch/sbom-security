"""Tests for how distribution packages are named and versioned for their advisories.

The Package URLs are as Syft reports them for the recorded test images.
"""

import pytest
from packageurl import PackageURL

from sbom_security.distribution import advisory_package, ecosystems, installed_version

OPENSSL_LIBS = PackageURL.from_string(
    "pkg:rpm/redhat/openssl-libs@3.5.8-1.el9_8?arch=x86_64&distro=rhel-9.8&epoch=1"
    "&upstream=openssl-3.5.8-1.el9_8.src.rpm"
)
ALTERNATIVES = PackageURL.from_string(
    "pkg:rpm/redhat/alternatives@1.24-2.el9?arch=x86_64&distro=rhel-9.8"
    "&upstream=chkconfig-1.24-2.el9.src.rpm"
)
LIBSSL = PackageURL.from_string(
    "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?arch=amd64&distro=debian-13.7"
    "&upstream=openssl"
)
BASH = PackageURL.from_string(
    "pkg:deb/debian/bash@5.2.37-2%2Bb10?arch=amd64&distro=debian-13.7"
    "&upstream=bash%405.2.37-2"
)
ZLIB = PackageURL.from_string(
    "pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bb1?arch=amd64&distro=debian-13.6"
    "&upstream=zlib%401%3A1.3.dfsg%2Breally1.3.1-1"
)
BASELAYOUT_DATA = PackageURL.from_string(
    "pkg:apk/alpine/alpine-baselayout-data@3.7.2-r1?arch=x86_64&distro=alpine-3.24.2"
    "&upstream=alpine-baselayout"
)


def test_red_hat_advisories_are_asked_for_in_each_repository():
    assert ecosystems(OPENSSL_LIBS) == (
        "Red Hat:enterprise_linux:9::baseos",
        "Red Hat:enterprise_linux:9::appstream",
        "Red Hat:enterprise_linux:9::crb",
    )


def test_an_rpms_epoch_comes_first():
    # Without it, every advisory fixed in a version with an epoch appears to apply.
    assert installed_version(OPENSSL_LIBS) == "1:3.5.8-1.el9_8"
    assert advisory_package(OPENSSL_LIBS) == ("openssl-libs", "1:3.5.8-1.el9_8")


def test_an_rpm_without_an_epoch_keeps_its_version():
    assert installed_version(ALTERNATIVES) == "1.24-2.el9"


def test_red_hat_names_the_binary_package_not_its_source():
    assert advisory_package(ALTERNATIVES) == ("alternatives", "1.24-2.el9")


def test_debian_advisories_are_asked_for_under_the_release():
    assert ecosystems(LIBSSL) == ("Debian:13",)


def test_a_debian_package_is_known_by_its_source_package():
    assert advisory_package(LIBSSL) == ("openssl", "3.5.7-1~deb13u3")


def test_a_rebuilt_debian_package_is_known_by_its_sources_version():
    assert installed_version(BASH) == "5.2.37-2+b10"
    assert advisory_package(BASH) == ("bash", "5.2.37-2")


def test_a_debian_version_keeps_its_epoch():
    assert advisory_package(ZLIB) == ("zlib", "1:1.3.dfsg+really1.3.1-1")


def test_alpine_advisories_are_asked_for_under_the_release_and_its_origin():
    assert ecosystems(BASELAYOUT_DATA) == ("Alpine:v3.24",)
    assert advisory_package(BASELAYOUT_DATA) == ("alpine-baselayout", "3.7.2-r1")


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04",
        "pkg:rpm/centos/bash@5.1.8-9.el9?arch=x86_64&distro=centos-9",
        "pkg:apk/alpine/musl@1.2.6-r2?arch=x86_64&distro=alpine-edge",
        "pkg:rpm/redhat/bash@5.1.8-9.el9?arch=x86_64",
        "pkg:deb/debian/apt?distro=debian-13.7",
        "pkg:npm/express@4.18.0",
    ],
)
def test_anything_not_handled_has_no_ecosystem(purl: str):
    assert ecosystems(PackageURL.from_string(purl)) == ()
