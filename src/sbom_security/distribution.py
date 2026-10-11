"""How a Linux distribution's packages are versioned, and where their advisories are.

A distribution package cannot be matched against upstream advisories. A fix often
arrives as a backport within the same upstream version, so openssl-3.0.7-25.el9 can be
fixed while upstream 3.0.7 is not. Each distribution publishes advisories for its own
packages, in its own version numbers, and OSV carries them. This module says how to
ask for them.

Every distribution files them differently, and asking the wrong way does not fail; it
returns wrong answers:

- The ecosystem must name the release. Asked about Debian in general rather than
  Debian 13, OSV compares a version against every release's fixes at once.
- Red Hat files advisories per repository, so a package is asked about in each
  repository a container image draws from. It belongs to only one of them.
- An RPM's epoch must come first. Without it ``3.5.8-1.el9_8`` sorts before every
  version that has one, and every old advisory appears to apply.
- Debian and Alpine file advisories under the source package, which Syft records as
  the ``upstream`` qualifier: ``libssl3t64`` is built from ``openssl``.

Distributions not handled here are left unassessed rather than guessed at.
"""

from packageurl import PackageURL

# Package URL types of distribution packages.
RPM = "rpm"
DEB = "deb"
APK = "apk"
PACKAGE_TYPES = (RPM, DEB, APK)

# The Red Hat repositories whose packages appear in container images.
RED_HAT_REPOSITORIES = ("baseos", "appstream", "crb")


def ecosystems(purl: PackageURL) -> tuple[str, ...]:
    """Return the OSV ecosystems a package's advisories are filed under.

    The release comes from the ``distro`` qualifier, such as ``rhel-9.8``. An empty
    answer means the distribution, or its release, is not one handled here.
    """
    if not purl.version:
        return ()
    name, _, release = (purl.qualifiers or {}).get("distro", "").partition("-")
    numbers = release.split(".")
    if not numbers[0].isdigit():
        return ()

    if (purl.type, purl.namespace, name) == (RPM, "redhat", "rhel"):
        return tuple(
            f"Red Hat:enterprise_linux:{numbers[0]}::{repository}"
            for repository in RED_HAT_REPOSITORIES
        )
    if (purl.type, purl.namespace, name) == (DEB, "debian", "debian"):
        return (f"Debian:{numbers[0]}",)
    if (purl.type, purl.namespace, name) == (APK, "alpine", "alpine") and len(numbers) > 1:
        return (f"Alpine:v{numbers[0]}.{numbers[1]}",)
    return ()


def installed_version(purl: PackageURL) -> str:
    """Return the version as the distribution writes it.

    A Package URL carries an RPM's epoch as a qualifier. Red Hat writes it in front of
    the version, as ``1:3.5.8-1.el9_8``, and so do its advisories.
    """
    epoch = (purl.qualifiers or {}).get("epoch")
    if purl.type == RPM and epoch:
        return f"{epoch}:{purl.version}"
    return purl.version or ""


def advisory_package(purl: PackageURL) -> tuple[str, str]:
    """Return the name and version a distribution's advisories know a package by.

    Red Hat names binary packages. Debian and Alpine name the source package a binary
    was built from, recorded as ``upstream``, sometimes with a version of its own: a
    Debian rebuild such as ``5.2.37-2+b10`` comes from source ``5.2.37-2``.
    """
    if purl.type == RPM:
        return purl.name, installed_version(purl)
    source = (purl.qualifiers or {}).get("upstream")
    if not source:
        return purl.name, installed_version(purl)
    name, at, version = source.partition("@")
    return name, version if at else installed_version(purl)
