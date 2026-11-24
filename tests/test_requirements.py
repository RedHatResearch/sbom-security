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


def test_reads_a_pin_with_hashes():
    # What pip-compile --generate-hashes writes.
    content = (
        "requests==2.31.0 \\\n"
        "    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f \\\n"
        "    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1\n"
        "    # via -r requirements.in\n"
        "flask==3.0.0 --hash=sha256:21128f47e4e3b9d597a3e8521a329bf56909b690fcc3fa3e477725aa81367638\n"
    )

    understood, ignored = parse_requirements_txt(content)

    assert understood == (
        Requirement("requests", "==2.31.0", PYPI),
        Requirement("flask", "==3.0.0", PYPI),
    )
    assert ignored == ()


def test_reads_a_requirement_spread_over_lines():
    understood, ignored = parse_requirements_txt("django>=4.2, \\\n  <5.0\nflask\n")

    assert [(item.name, set(item.range.split(","))) for item in understood] == [
        ("django", {">=4.2", "<5.0"}),
        ("flask", {""}),
    ]
    assert ignored == ()


def test_a_comment_does_not_continue_onto_the_next_line():
    understood, _ = parse_requirements_txt("# a comment \\\nflask==3.0.0\n")

    assert understood == (Requirement("flask", "==3.0.0", PYPI),)


def test_a_comment_ends_a_continued_line():
    understood, _ = parse_requirements_txt("flask==3.0.0 \\\n# a comment\ndjango==4.2.0\n")

    assert [item.name for item in understood] == ["flask", "django"]


def test_reads_a_last_line_that_ends_in_a_backslash():
    understood, _ = parse_requirements_txt("flask==3.0.0 \\")

    assert understood == (Requirement("flask", "==3.0.0", PYPI),)


def test_a_marker_is_not_taken_for_an_option():
    understood, ignored = parse_requirements_txt('tomli==2.0.1 ; python_version < "3.11"\n')

    assert understood == (Requirement("tomli", "==2.0.1", PYPI),)
    assert ignored == ()


def test_a_line_that_is_not_understood_is_recorded_whole():
    _, ignored = parse_requirements_txt("not a requirement --hash=sha256:00\n")

    assert ignored == ("not a requirement --hash=sha256:00",)
