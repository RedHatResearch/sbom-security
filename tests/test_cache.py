"""Tests for the on-disk SBOM cache."""

from pathlib import Path

from sbom_security.cache import SbomCache
from sbom_security.models import PackageRef, Sbom

EXPRESS = Sbom(
    purl="pkg:npm/express@4.18.0",
    dependencies=(PackageRef("accepts", "1.3.8"), PackageRef("cookie", "0.5.0")),
)


def test_stores_and_returns_an_sbom(tmp_path: Path):
    cache = SbomCache(tmp_path)

    cache.put(EXPRESS)

    assert cache.get(EXPRESS.purl) == EXPRESS


def test_reports_a_missing_entry_as_absent(tmp_path: Path):
    cache = SbomCache(tmp_path)

    assert cache.get("pkg:npm/nothing@1.0.0") is None
    assert cache.has("pkg:npm/nothing@1.0.0") is False


def test_knows_what_it_holds(tmp_path: Path):
    cache = SbomCache(tmp_path)

    cache.put(EXPRESS)

    assert cache.has(EXPRESS.purl) is True


def test_replaces_an_existing_entry(tmp_path: Path):
    cache = SbomCache(tmp_path)
    cache.put(EXPRESS)

    updated = Sbom(purl=EXPRESS.purl, dependencies=(PackageRef("accepts", "1.3.9"),))
    cache.put(updated)

    assert cache.get(EXPRESS.purl) == updated


def test_a_scoped_name_stays_one_flat_file(tmp_path: Path):
    # A name containing a slash must not become a directory, or a crafted package
    # name could write outside the cache.
    cache = SbomCache(tmp_path)
    scoped = Sbom(purl="pkg:npm/%40babel/core@7.20.12", dependencies=())

    cache.put(scoped)

    assert cache.get(scoped.purl) == scoped
    assert [path.is_file() for path in tmp_path.iterdir()] == [True]


def test_leaves_no_temporary_files_behind(tmp_path: Path):
    cache = SbomCache(tmp_path)

    cache.put(EXPRESS)

    assert [path.suffix for path in tmp_path.iterdir()] == [".json"]


def test_stores_an_sbom_with_no_dependencies(tmp_path: Path):
    cache = SbomCache(tmp_path)
    leaf = Sbom(purl="pkg:npm/ms@2.1.3", dependencies=())

    cache.put(leaf)

    assert cache.get(leaf.purl) == leaf
