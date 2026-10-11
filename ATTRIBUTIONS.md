# Attributions

Third-party work this project builds on, recorded at the time it is adopted rather
than retroactively.

This project is licensed under Apache-2.0. Reused components must carry a compatible
license: Apache-2.0 and MIT are compatible, AGPL is not.

The complete set of installed dependencies is declared in `pyproject.toml`. This file
records what was deliberately taken and what it replaces, which the dependency list
alone does not convey.

## Data sources

| Source | Where | License | Used for |
| ------ | ----- | ------- | -------- |
| OSV.dev | https://osv.dev | Records carry their upstream licenses; see osv.dev | The vulnerability database and its schema. Aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability database and around twenty further feeds, along with the advisories Red Hat, Debian and Alpine publish for their own packages, so this project does not maintain a vulnerability database of its own. |
| deps.dev | https://deps.dev | See deps.dev | Resolved dependency graphs per package version. A package declares version ranges, and turning those into exact versions means reimplementing part of npm's resolver; deps.dev has already done it. |
| CVE records | https://www.cve.org | CVE Terms of Use, © The MITRE Corporation | The cases of the CVE extraction dataset in `evaluation/`, reproduced unchanged with MITRE's copyright designation and license. |
| endoflife.date | https://endoflife.date | MIT | Support lifecycles per release line, and which Package URLs belong to which product. Many projects publish how long each release line is supported, but no package registry records it; endoflife.date collects it for several hundred products. |

## Libraries

| Component | Where | License | Used for |
| --------- | ----- | ------- | -------- |
| packageurl-python | https://github.com/package-url/packageurl-python | MIT | Building and parsing Package URLs, rather than reimplementing the specification |
| packaging | https://github.com/pypa/packaging | Apache-2.0 / BSD-2-Clause | Parsing and comparing Python requirements and versions. PEP 440 versions do not compare like semver, and the PyPA implementation is the reference for how pip reads the same files. |
| node-semver | https://github.com/podhmo/python-node-semver | MIT | Resolving npm version ranges to published versions. A manifest declares ranges (`^4.18.0`), and npm's range syntax is large enough that implementing it would introduce a class of silently wrong matches. |
| arq | https://github.com/python-arq/arq | MIT | The work queue. Chosen over Celery because it is built for asyncio, which the rest of this project already uses, and because the work here is uniform and parallel rather than orchestrated. It is confined to `queue.py` and `worker.py`; the work itself has no knowledge of it. |

## Tools

Programs this project runs, rather than imports.

| Tool | Where | License | Used for |
| ---- | ----- | ------- | -------- |
| Syft | https://github.com/anchore/syft | Apache-2.0 | Finding the packages inside a container image, read straight from its registry without running it. Reading image layers here would mean reimplementing whiteouts, multi-architecture images, and RPM databases kept in more than one on-disk format. Syft is also the tool Red Hat Trusted Profile Analyzer documents for generating SBOMs from images. Copied into the Docker image from its official image, pinned by digest. |

## Designs adopted without reusing code

The components identified as reusable during the competitor analysis are written in Go
or Ruby and cannot be imported into a Python project. Their designs carried over
instead:

- **Syft and Grype** (Apache-2.0, Go) — separating "produce the inventory" from
  "analyze the inventory", which is why parsing and matching are distinct here. Syft
  itself has since been adopted as a tool, for container images.
- **Dependabot** (MIT, Ruby) — one self-contained parser per ecosystem behind a common
  interface.
- **OWASP Dependency-Check** (Apache-2.0, Java) — a counter-example: its CPE-based
  matching is the documented source of its false positives, which is why this project
  matches on Package URLs instead.

Adopted later in the same way:

- **xeol** (Apache-2.0, Go) — finding a package's product by its Package URL, and
  placing a version on a release line by comparing numbers rather than text. This
  project additionally picks the most specific line where several match, and reports
  active and limited support rather than end of life alone.
- **SPDX 3.0** — the support vocabulary. Statuses are named so that each corresponds to
  an SPDX `supportLevel` value, and `limited` follows SPDX's `limitedSupport`.
