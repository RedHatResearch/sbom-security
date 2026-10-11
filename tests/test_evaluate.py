"""Tests for the CVE extraction runner, its baseline, and the dataset itself.

The runner lives outside the package so that it needs nothing installed, so it is
loaded here from its file.
"""

import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType

import pytest

EVALUATION = Path(__file__).parent.parent / "evaluation"
DATASET = EVALUATION / "cve-extraction"
CASES = sorted(path for path in (DATASET / "cases").iterdir() if path.is_dir())


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EVALUATION / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up while being defined
    spec.loader.exec_module(module)
    return module


evaluate = load("evaluate")
fields_only = load("fields_only")


def expected_answer(case: str) -> dict:
    return json.loads((DATASET / "cases" / case / "expected.json").read_text(encoding="utf-8"))


def failed_fields(checks) -> set[str]:
    return {check.field for check in checks if not check.passed}


EXPRESS = {
    "id": "CVE-0000-0001",
    "status": "published",
    "replaced_by": None,
    "affected": [
        {
            "product": "express",
            "purl": "pkg:npm/express",
            "ranges": [{"introduced": "0", "fixed": "4.20.0"}],
            "versions": [],
        }
    ],
    "cwe": ["CWE-79"],
    "category": "happy",
    "notes": None,
}

CURL = {
    **EXPRESS,
    "affected": [
        {
            "product": "curl",
            "purl": None,
            "ranges": [{"introduced": "7.69.0", "fixed": "8.4.0"}],
            "versions": [],
        }
    ],
    "cwe": [],
}


@pytest.mark.parametrize("case", CASES, ids=lambda path: path.name)
def test_every_case_is_well_formed(case: Path):
    document = json.loads((case / "document.json").read_text(encoding="utf-8"))
    expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))

    assert expected["id"] == case.name == document["cveMetadata"]["cveId"]
    assert expected["status"] == document["cveMetadata"]["state"].lower()
    assert expected["category"] in ("happy", "unhappy", "edge")
    for entry in expected["affected"]:
        assert set(entry) == {"product", "purl", "ranges", "versions"}
        for item in entry["ranges"]:
            assert "introduced" in item
            assert set(item) <= {"introduced", "fixed", "last_affected"}


@pytest.mark.parametrize("case", CASES, ids=lambda path: path.name)
def test_the_expected_answer_scores_perfectly(case: Path):
    # Catches a mistake in an expected answer as much as one in the scoring.
    expected = expected_answer(case.name)

    checks, invented = evaluate.score(expected, expected)

    assert failed_fields(checks) == set()
    assert invented == []


def test_a_product_not_found_fails():
    answer = {**EXPRESS, "affected": []}

    checks, _ = evaluate.score(EXPRESS, answer)

    # Everything about the product counts as missed, so silence never beats a wrong answer.
    assert failed_fields(checks) == {"affected", "purl", "versions"}


def test_a_package_url_is_compared_however_it_is_spelled():
    expected = {**EXPRESS, "affected": [{**EXPRESS["affected"][0], "purl": "pkg:npm/%40babel/traverse"}]}
    answer = {**expected, "affected": [{**expected["affected"][0], "purl": "pkg:npm/@babel/traverse@7.23.2"}]}

    checks, _ = evaluate.score(expected, answer)

    assert failed_fields(checks) == set()


def test_software_without_a_package_url_is_found_by_name():
    answer = {**CURL, "affected": [{**CURL["affected"][0], "product": "Curl"}]}

    checks, _ = evaluate.score(CURL, answer)

    assert failed_fields(checks) == set()


def test_a_wrong_range_fails():
    answer = {**EXPRESS, "affected": [{**EXPRESS["affected"][0], "ranges": [{"introduced": "0", "fixed": "4.19.0"}]}]}

    checks, _ = evaluate.score(EXPRESS, answer)

    assert failed_fields(checks) == {"versions"}


def test_a_range_where_individual_versions_are_expected_fails():
    expected = expected_answer("CVE-2024-3094")
    entry = {**expected["affected"][0], "ranges": [{"introduced": "5.6.0", "fixed": "5.6.2"}]}
    answer = {**expected, "affected": [{**entry, "versions": []}]}

    checks, _ = evaluate.score(expected, answer)

    assert failed_fields(checks) == {"versions"}


def test_a_product_is_found_by_a_name_that_contains_it():
    entry = {**EXPRESS["affected"][0], "purl": None, "product": "express node module"}

    checks, invented = evaluate.score(EXPRESS, {**EXPRESS, "affected": [entry]})

    assert failed_fields(checks) == {"purl"}
    assert invented == []


def test_a_broader_name_does_not_stand_for_a_narrower_package():
    expected = expected_answer("CVE-2023-45133")
    entry = {"product": "babel", "purl": None, "ranges": [], "versions": []}

    checks, invented = evaluate.score(expected, {**expected, "affected": [entry]})

    assert "affected" in failed_fields(checks)
    assert invented == ["a product the expected answer does not list: babel"]


def test_a_package_url_for_software_that_has_none_is_invented():
    answer = {**CURL, "affected": [{**CURL["affected"][0], "purl": "pkg:generic/curl"}]}

    checks, invented = evaluate.score(CURL, answer)

    assert failed_fields(checks) == {"purl"}
    assert len(invented) == 1


def test_a_product_the_record_does_not_name_is_invented():
    extra = {"product": "body-parser", "purl": "pkg:npm/body-parser", "ranges": [], "versions": []}
    answer = {**EXPRESS, "affected": [*EXPRESS["affected"], extra]}

    checks, invented = evaluate.score(EXPRESS, answer)

    assert failed_fields(checks) == set()
    assert invented == ["a product the expected answer does not list: pkg:npm/body-parser"]


def test_a_weakness_the_record_does_not_give_is_invented():
    answer = {**EXPRESS, "cwe": ["CWE-79", "CWE-601"]}

    checks, invented = evaluate.score(EXPRESS, answer)

    assert failed_fields(checks) == {"cwe"}
    assert invented == ["a weakness the record does not give: CWE-601"]


def test_a_rejected_duplicate_must_name_its_replacement():
    expected = expected_answer("CVE-2024-9840")

    checks, _ = evaluate.score(expected, {**expected, "replaced_by": None})

    assert failed_fields(checks) == {"replaced_by"}


def test_the_baseline_gets_well_filled_records_right_and_prose_wrong():
    results = {
        result.case: result
        for result in evaluate.evaluate(
            DATASET, evaluate.command_tool(f"{sys.executable} {EVALUATION / 'fields_only.py'}")
        )
    }

    assert len(results) == len(CASES)
    assert failed_fields(results["CVE-2026-74866"].checks) == set()
    # bzip2 is named only in the description, so a reader of fields finds nothing.
    assert "affected" in failed_fields(results["CVE-2019-12900"].checks)
    assert "affected" in failed_fields(results["CVE-2022-24999"].checks)


def test_a_tool_that_fails_gets_no_credit():
    results = evaluate.evaluate(
        DATASET, evaluate.command_tool(f"{sys.executable} -c 'import sys; sys.exit(3)'")
    )

    assert all(result.error for result in results)
    assert not any(check.passed for result in results for check in result.checks)


def test_an_answer_that_is_not_json_is_no_answer():
    results = evaluate.evaluate(DATASET, evaluate.command_tool(f"{sys.executable} -c 'print(1, 2)'"))

    assert results[0].error == "the answer is not JSON"


def test_a_tool_can_be_reached_over_http():
    class Oracle(BaseHTTPRequestHandler):
        """Answers each record with its expected answer."""

        def do_POST(self):  # pylint: disable=invalid-name
            document = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = json.dumps(expected_answer(document["cveMetadata"]["cveId"])).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Oracle)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/extract"
        totals = evaluate.summary(evaluate.evaluate(DATASET, evaluate.url_tool(url)))
    finally:
        server.shutdown()

    assert totals["overall"]["score"] == 1.0
    assert totals["invented"] == 0


def test_a_score_below_the_minimum_fails_the_run(tmp_path: Path, capsys):
    command = f"{sys.executable} {EVALUATION / 'fields_only.py'}"
    report = tmp_path / "report.json"

    status = evaluate.main(["--command", command, "--min-score", "0.99", "--report", str(report)])

    assert status == 1
    assert "Overall" in capsys.readouterr().out
    assert len(json.loads(report.read_text())["cases"]) == len(CASES)
