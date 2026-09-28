"""Tests for reading Python requirements files."""

from sbom_security.models import PYPI, Requirement
from sbom_security.requirements import parse_requirements_txt


def test_reads_a_pinned_requirement():
    understood, ignored = parse_requirements_txt("django==4.2.0\n")

    assert understood == (Requirement("django", "==4.2.0", PYPI),)
    assert ignored == ()


def test_reads_a_range():
    understood, _ = parse_requirements_txt("requests>=2.28,<3.0\n")

    assert understood[0].name == "requests"
    assert understood[0].ecosystem == PYPI


def test_a_requirement_without_a_specifier_means_any_version():
    understood, _ = parse_requirements_txt("flask\n")

    assert understood == (Requirement("flask", "", PYPI),)


def test_skips_blank_lines_and_comments():
    content = "\n# a comment\n\ndjango==4.2.0\n"

    understood, ignored = parse_requirements_txt(content)

    assert understood == (Requirement("django", "==4.2.0", PYPI),)
    assert ignored == ()


def test_strips_a_trailing_comment():
    understood, _ = parse_requirements_txt("django==4.2.0  # the web framework\n")

    assert understood == (Requirement("django", "==4.2.0", PYPI),)


def test_records_directives_rather_than_dropping_them():
    # -r points at another file this does not follow, so what it names is missing
    # from the report and the caller should know.
    understood, ignored = parse_requirements_txt("-r base.txt\ndjango==4.2.0\n")

    assert understood == (Requirement("django", "==4.2.0", PYPI),)
    assert ignored == ("-r base.txt",)


def test_records_a_requirement_pointing_at_a_url():
    content = "mypkg @ https://example.com/mypkg-1.0.tar.gz\n"

    understood, ignored = parse_requirements_txt(content)

    assert understood == ()
    assert ignored == ("mypkg @ https://example.com/mypkg-1.0.tar.gz",)


def test_records_a_line_it_cannot_parse():
    understood, ignored = parse_requirements_txt("this is not a requirement\n")

    assert understood == ()
    assert ignored == ("this is not a requirement",)


def test_reads_several_requirements():
    content = "django==4.2.0\nrequests>=2.28\nflask\n"

    understood, _ = parse_requirements_txt(content)

    assert [item.name for item in understood] == ["django", "requests", "flask"]


def test_an_empty_file_yields_nothing():
    assert parse_requirements_txt("") == ((), ())
