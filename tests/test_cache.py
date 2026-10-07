"""Tests for the on-disk caches."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sbom_security.cache import ExpiringCache, SbomCache, Stored
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


RETRIEVED = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
PACKAGE_URLS = Stored(
    document={"result": [{"identifier": "pkg:npm/express"}]}, retrieved_at=RETRIEVED
)


def test_keeps_a_document_together_with_when_it_was_retrieved(tmp_path: Path):
    cache = ExpiringCache(tmp_path)

    cache.put("identifiers/purl", PACKAGE_URLS)

    assert cache.get("identifiers/purl") == PACKAGE_URLS


def test_reports_a_missing_document_as_absent(tmp_path: Path):
    assert ExpiringCache(tmp_path).get("products/express") is None


def test_a_document_is_fresh_only_within_its_lifetime(tmp_path: Path):
    cache = ExpiringCache(tmp_path, lifetime=timedelta(days=30))

    assert cache.is_fresh(PACKAGE_URLS, RETRIEVED + timedelta(days=29))
    assert not cache.is_fresh(PACKAGE_URLS, RETRIEVED + timedelta(days=30))


def test_an_expired_document_is_still_returned(tmp_path: Path):
    # When the source cannot be reached, an old answer that states its age beats no
    # answer at all, so expiry is the caller's decision rather than a deletion.
    cache = ExpiringCache(tmp_path, lifetime=timedelta(days=1))
    cache.put("identifiers/purl", PACKAGE_URLS)

    assert cache.get("identifiers/purl") == PACKAGE_URLS


def test_a_key_with_slashes_stays_one_flat_file(tmp_path: Path):
    cache = ExpiringCache(tmp_path)

    cache.put("products/express", PACKAGE_URLS)

    assert [path.name for path in tmp_path.iterdir()] == ["products%2Fexpress.json"]
