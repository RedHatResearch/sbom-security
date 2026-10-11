# Evaluation

Measuring tools whose output is judged against a reference rather than checked by
ordinary tests.

## CVE extraction

A CVE record says in prose and in loosely filled fields what is affected. Turning it
into structured data, which package and which versions, is the step that needs
measuring before a tool for it can be trusted.

- `cve-extraction/` holds the cases: records as published, each with the answer a
  careful reader should get from it. Its README describes the format.
- `evaluate.py` measures a tool against them. It needs nothing beyond Python's
  standard library, so it runs wherever the tool does.
- `fields_only.py` is a baseline that copies the structured fields and reads no text.

### The tool under test

It can be written in anything, and is reached one of two ways:

| Option | The tool receives | And answers with |
| ------ | ----------------- | ---------------- |
| `--command "..."` | the record on standard input | JSON on standard output |
| `--url http://...` | the record as the body of a JSON `POST` | a JSON response |

The answer has the shape of `expected.json`, without `category` and `notes`.

```bash
python3 evaluation/evaluate.py --command "python3 evaluation/fields_only.py"
python3 evaluation/evaluate.py --url http://localhost:8000/extract
```

`--report results.json` also writes every check, case by case. `--min-score 0.8` exits
with 1 below that score, for use in CI. `--timeout` bounds each case, 60 seconds by
default.

### How answers are scored

- Each affected product in the expected answer has to be found, by Package URL where
  it has one and otherwise by name. Then its Package URL, and the versions it is said
  to be affected in, ranges and individual versions together, are compared exactly.
- A product that is not found fails every check it would have had, so that answering
  nothing never scores better than answering wrongly.
- The record's status and CWE identifiers are compared for every case, and the
  replacement for a rejected duplicate where the record names one.
- Anything stated that the expected answer does not support is also counted apart as
  **invented**: a product it does not list, a Package URL for software that has none, a
  weakness the record does not give.

Read the results by field rather than overall. Status and CWE are easy, so they lift
the overall score; Package URL and versions are where extraction is hard.

### The baseline

`fields_only.py`, on the first version of the dataset:

| Field | Score |
| ----- | ----- |
| status | 23/23 |
| replaced_by | 0/1 |
| affected | 17/22 |
| purl | 8/22 |
| versions | 7/22 |
| cwe | 23/23 |
| **Overall** | **78/113, 69%** |

Few records name the package ecosystem outright, so the Package URL is mostly missed,
and most keep their versions in prose. That is the gap a real extractor has to close.
