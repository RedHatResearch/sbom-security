"""Tests for the endoflife.date support source.

Requests are answered by a fake and the clock is fixed, so the suite never touches
the network and never depends on what today is.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from sbom_security.cache import ExpiringCache
from sbom_security.endoflife import EndOfLifeClient
from sbom_security.models import (
    ACTIVE,
    END_OF_LIFE,
    LIMITED,
    PUBLISHED,
    PYPI,
    SUPPORTED,
    PackageRef,
    Support,
)
from sbom_security.purl import to_dependency

TODAY = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)

PACKAGE_URLS = {
    "result": [
        {"identifier": "pkg:npm/express", "product": {"name": "express"}},
        {"identifier": "pkg:npm/%40angular/core", "product": {"name": "angular"}},
        {"identifier": "pkg:npm/layered", "product": {"name": "layered"}},
        {"identifier": "pkg:pypi/django", "product": {"name": "django"}},
        {"identifier": "pkg:npm/withdrawn", "product": {"name": "withdrawn"}},
        # Entries that cannot be read, which must not cost the others their answers.
        {"identifier": "not a package url", "product": {"name": "broken"}},
        {"identifier": "pkg:npm/no-product"},
    ]
}

PRODUCTS: dict[str, dict[str, Any]] = {
    # Express does not distinguish a main period of support from a later one.
    "express": {
        "name": "express",
        "labels": {"eoas": None, "eol": "Security Support"},
        "links": {"html": "https://endoflife.date/express"},
        "releases": [
            {"name": "5", "isEol": False, "eolFrom": None},
            {"name": "4", "isEol": False, "eolFrom": None},
            {"name": "3", "isEol": True, "eolFrom": "2015-07-05"},
        ],
    },
    "angular": {
        "name": "angular",
        "labels": {"eoas": "Active Support", "eol": "Security Support"},
        "links": {"html": "https://endoflife.date/angular"},
        "releases": [
            {"name": "22", "isEoas": False, "eoasFrom": "2027-06-30",
             "isEol": False, "eolFrom": "2028-06-30"},
            {"name": "21", "isEoas": True, "eoasFrom": "2026-06-03",
             "isEol": False, "eolFrom": "2027-06-30"},
            # Ended, but without a date ever being recorded.
            {"name": "12", "isEoas": True, "eoasFrom": None,
             "isEol": True, "eolFrom": None},
        ],
    },
    # Lines named at more than one depth, one of them a textual prefix of another.
    "layered": {
        "name": "layered",
        "labels": {"eoas": None, "eol": "Support"},
        "links": {"html": "https://endoflife.date/layered"},
        "releases": [
            {"name": "3.4", "isEol": False, "eolFrom": None},
            {"name": "3", "isEol": False, "eolFrom": None},
            {"name": "2.10", "isEol": False, "eolFrom": None},
            {"name": "2.1", "isEol": True, "eolFrom": "2020-01-01"},
        ],
    },
    "django": {
        "name": "django",
        "labels": {"eoas": "Active Support", "eol": "Security Support"},
        "links": {"html": "https://endoflife.date/django"},
        "releases": [
            {"name": "5.2", "isEoas": True, "eoasFrom": "2025-12-03",
             "isEol": False, "eolFrom": "2028-04-30"},
            {"name": "4.2", "isEoas": True, "eoasFrom": "2023-12-04",
             "isEol": True, "eolFrom": "2026-04-07"},
        ],
    },
}


class FakeEndOfLife:
    """Answers endoflife.date requests from canned data and records what was asked.

    ``down`` makes every request fail, as when the service cannot be reached.
    """

    def __init__(self, down: bool = False):
        self.down = down
        self.paths: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if self.down:
            return httpx.Response(503)
        if request.url.path == "/api/v1/identifiers/purl":
            return httpx.Response(200, json=PACKAGE_URLS)
        name = request.url.path.rsplit("/", 1)[-1]
        if name not in PRODUCTS:
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"result": PRODUCTS[name]})

    def client(self, directory: Path, today: datetime = TODAY) -> EndOfLifeClient:
        return EndOfLifeClient(
            cache=ExpiringCache(directory),
            transport=httpx.MockTransport(self),
            clock=lambda: today,
        )


async def support_of(
    ref: PackageRef, directory: Path, today: datetime = TODAY
) -> Support | None:
    """Look up one package version, as a report would."""
    dependency = to_dependency(ref)
    found = await FakeEndOfLife().client(directory, today).find_support([dependency])
    return found.get(dependency.purl)


async def test_reports_the_line_a_version_belongs_to(tmp_path: Path):
    support = await support_of(PackageRef("express", "4.18.0"), tmp_path)

    assert support is not None
    assert support.line == "4"
    assert support.basis == PUBLISHED
    assert support.source == "https://endoflife.date/express"


async def test_a_project_without_a_main_period_is_only_said_to_be_supported(
    tmp_path: Path,
):
    support = await support_of(PackageRef("express", "4.18.0"), tmp_path)

    assert support.status == SUPPORTED
    assert support.phase == "Security Support"
    assert support.active_support_until is None


async def test_a_line_in_its_main_period_is_active(tmp_path: Path):
    support = await support_of(PackageRef("@angular/core", "22.1.0"), tmp_path)

    assert support.status == ACTIVE
    assert support.phase == "Active Support"
    assert support.active_support_until == "2027-06-30"
    assert support.support_until == "2028-06-30"


async def test_a_line_past_its_main_period_has_limited_support(tmp_path: Path):
    support = await support_of(PackageRef("@angular/core", "21.2.0"), tmp_path)

    assert support.status == LIMITED
    assert support.phase == "Security Support"


async def test_a_line_past_its_end_of_life_gets_no_fixes(tmp_path: Path):
    support = await support_of(PackageRef("express", "3.21.2"), tmp_path)

    assert support.status == END_OF_LIFE
    assert support.phase is None
    assert support.support_until == "2015-07-05"


async def test_the_status_follows_the_dates_not_the_stored_flags(tmp_path: Path):
    # The flags were true on the day endoflife.date generated the document. Kept for
    # weeks they go stale; the dates do not.
    later = datetime(2027, 7, 1, tzinfo=timezone.utc)

    support = await support_of(PackageRef("@angular/core", "22.1.0"), tmp_path, later)

    assert support.status == LIMITED


async def test_support_ends_on_the_announced_day(tmp_path: Path):
    last_day = datetime(2028, 6, 30, tzinfo=timezone.utc)

    support = await support_of(PackageRef("@angular/core", "22.1.0"), tmp_path, last_day)

    assert support.status == END_OF_LIFE


async def test_a_flag_decides_where_no_date_was_recorded(tmp_path: Path):
    support = await support_of(PackageRef("@angular/core", "12.2.17"), tmp_path)

    assert support.status == END_OF_LIFE
    assert support.support_until is None


async def test_lines_are_compared_number_by_number_not_as_text(tmp_path: Path):
    # As text, "2.1" is a prefix of "2.10.3".
    newer = await support_of(PackageRef("layered", "2.10.3"), tmp_path)
    older = await support_of(PackageRef("layered", "2.1.5"), tmp_path)

    assert newer.line == "2.10"
    assert older.line == "2.1"


async def test_the_most_specific_line_wins(tmp_path: Path):
    specific = await support_of(PackageRef("layered", "3.4.2"), tmp_path)
    general = await support_of(PackageRef("layered", "3.5.0"), tmp_path)

    assert specific.line == "3.4"
    assert general.line == "3"


async def test_a_prerelease_belongs_to_its_line(tmp_path: Path):
    support = await support_of(PackageRef("express", "5.0.0-beta.3"), tmp_path)

    assert support.line == "5"


async def test_python_versions_are_read_as_pip_reads_them(tmp_path: Path):
    # An epoch's digits come first but say nothing about the release line.
    with_epoch = await support_of(PackageRef("django", "1!5.2.1", PYPI), tmp_path)
    candidate = await support_of(PackageRef("django", "5.2rc1", PYPI), tmp_path)

    assert with_epoch.line == "5.2"
    assert candidate.line == "5.2"


async def test_a_version_on_no_listed_line_gets_no_answer(tmp_path: Path):
    assert await support_of(PackageRef("express", "6.0.0"), tmp_path) is None


async def test_a_package_endoflife_does_not_cover_gets_no_answer(tmp_path: Path):
    assert await support_of(PackageRef("lodash", "4.17.21"), tmp_path) is None


async def test_a_product_that_no_longer_exists_gets_no_answer(tmp_path: Path):
    # The list still names it, but the product itself is gone. That is an answer from
    # the source, not a failure to reach it.
    assert await support_of(PackageRef("withdrawn", "1.0.0"), tmp_path) is None


async def test_unreadable_entries_do_not_cost_other_answers(tmp_path: Path):
    # The list holds an entry that is not a Package URL and one without a product.
    assert await support_of(PackageRef("express", "4.18.0"), tmp_path) is not None


async def test_asks_nothing_when_there_are_no_dependencies(tmp_path: Path):
    fake = FakeEndOfLife()

    assert await fake.client(tmp_path).find_support([]) == {}
    assert fake.paths == []


async def test_fetches_each_product_once_however_many_versions_use_it(tmp_path: Path):
    fake = FakeEndOfLife()
    dependencies = [
        to_dependency(PackageRef("express", "4.18.0")),
        to_dependency(PackageRef("express", "3.21.2")),
    ]

    found = await fake.client(tmp_path).find_support(dependencies)

    assert len(found) == 2
    assert fake.paths.count("/api/v1/products/express") == 1


async def test_asks_again_only_once_the_data_has_expired(tmp_path: Path):
    fake = FakeEndOfLife()
    express = [to_dependency(PackageRef("express", "4.18.0"))]

    await fake.client(tmp_path).find_support(express)
    await fake.client(tmp_path, TODAY + timedelta(days=29)).find_support(express)
    assert fake.paths.count("/api/v1/products/express") == 1

    await fake.client(tmp_path, TODAY + timedelta(days=31)).find_support(express)
    assert fake.paths.count("/api/v1/products/express") == 2


async def test_falls_back_on_expired_data_when_the_source_is_down(tmp_path: Path):
    express = to_dependency(PackageRef("express", "4.18.0"))
    await FakeEndOfLife().client(tmp_path).find_support([express])

    later = TODAY + timedelta(days=60)
    found = await FakeEndOfLife(down=True).client(tmp_path, later).find_support([express])

    # The answer is still given, and says how old it is.
    assert found[express.purl].line == "4"
    assert found[express.purl].retrieved_at == "2026-10-07T12:00:00+00:00"


async def test_fails_when_the_source_is_down_and_nothing_is_kept(tmp_path: Path):
    express = to_dependency(PackageRef("express", "4.18.0"))

    with pytest.raises(httpx.HTTPStatusError):
        await FakeEndOfLife(down=True).client(tmp_path).find_support([express])


async def test_says_when_the_data_was_retrieved(tmp_path: Path):
    support = await support_of(PackageRef("express", "4.18.0"), tmp_path)

    assert support.retrieved_at == "2026-10-07T12:00:00+00:00"
