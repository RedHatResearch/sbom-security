# sbom-security

[![tests](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml)

Report the dependencies of a package, repository or container image, the known
vulnerabilities affecting them, and whether each is still supported. Covers npm and
Python.

## Quick start

```bash
git clone https://github.com/RedHatResearch/sbom-security.git
cd sbom-security
docker compose up -d
```

Scan a real repository:

```bash
curl 'http://127.0.0.1:8010/reports/github?owner=OWASP&repo=NodeGoat&limit=3000'
```

That returns every dependency in the project and the CVEs affecting them. On OWASP
NodeGoat that is 1091 packages, 130 of them vulnerable, in a few seconds.

Interactive API documentation: **http://127.0.0.1:8010/docs**

## Endpoints

| Endpoint | Purpose |
| -------- | ------- |
| `GET /reports/github?owner=&repo=` | Scan a public GitHub repository |
| `POST /reports/npm-lockfile` | Scan a `package-lock.json` sent as the body |
| `GET /reports/npm-package?name=&version=` | Scan a package and its dependencies |
| `GET /reports/image?reference=` | Scan a container image, read from its registry |
| `POST /jobs/npm-package?name=&version=` | Hand a scan to a worker, collect it later |
| `POST /jobs/image?reference=` | Hand an image scan to a worker, collect it later |
| `GET /jobs/{id}` | Status and result of submitted work |
| `GET /queue` | How much work is waiting, and what is running |
| `GET /health` | Liveness check |

## Usage

**A public repository.** Nothing is cloned, no package manager runs, and no code from
the repository is executed — only its dependency files are read.

```bash
curl 'http://127.0.0.1:8010/reports/github?owner=OWASP&repo=NodeGoat'
```

The repository is read from whichever of these it has, in order:

| File | Ecosystem | Versions |
| ---- | --------- | -------- |
| `package-lock.json` | npm | Already exact |
| `package.json` | npm | Ranges, resolved against the registry |
| `requirements.txt` | Python | Pins or ranges, resolved against PyPI |

**A lockfile you already have.**

```bash
curl -X POST http://127.0.0.1:8010/reports/npm-lockfile \
  -H 'Content-Type: application/json' \
  --data-binary @package-lock.json
```

**A package, with no lockfile anywhere.** The whole dependency tree is walked unless
`depth` asks for less.

```bash
curl 'http://127.0.0.1:8010/reports/npm-package?name=express&version=4.18.0'
curl 'http://127.0.0.1:8010/reports/npm-package?name=express&version=4.18.0&depth=1'
```

`version` may also be a range, or left out entirely:

| Asked for | Gets |
| --------- | ---- |
| `version=4.18.0` | that exact version |
| `version=^4.0.0` | the newest that does not cross a major boundary |
| *omitted* | the newest release |

The report always names the version it settled on, never the range — so a scan of
`express` records `express@5.0.0`, and `generated_at` says when that was what newest
meant. That way a package can be asked about once rather than re-registered at every
release.

A walk runs to the bottom of the tree, bounded by a ceiling on how many packages one
request may examine. Depth cannot be predicted from outside, but the amount of work a
single request causes can be — and a walk stopped by that ceiling is marked
`"truncated": true`.

**A container image.** Read straight from its registry by
[Syft](https://github.com/anchore/syft): the image is never run and no container
runtime is needed.

```bash
curl 'http://127.0.0.1:8010/reports/image?reference=bkimminich/juice-shop&limit=3000'
```

`reference` is written as for `docker pull`. The report names the image by digest as
well as by the reference asked for, since a tag such as `latest` can point at a
different image tomorrow.

npm and Python packages found in the image are matched like any other dependency.
Operating system packages are matched against their distribution's own advisories
rather than upstream ones, because a distribution often fixes a vulnerability by
backporting the patch without changing the upstream version: `openssl-3.0.7-25.el9`
can be fixed while upstream 3.0.7 is not. That covers Red Hat Enterprise Linux,
including UBI images, Debian and Alpine. Packages from other distributions are listed
under `not_assessed` rather than matched wrongly.

Reading an image takes from seconds to minutes, so for a large one submit it as work
(`POST /jobs/image?reference=...`). A report on a tag is then reused for up to an hour.

Images are accepted from public registries only — Docker Hub, Quay, GitHub, Google,
Red Hat, Amazon, Microsoft and Kubernetes — so that a caller cannot make the service
connect anywhere else. Set `SBOM_IMAGE_REGISTRIES` to a comma-separated list of
registries to change that.

### The report

```json
{
  "schema_version": "1.3",
  "tool": "sbom-security",
  "generated_at": "2026-09-28T09:15:00+00:00",
  "target": {
    "name": "OWASP/NodeGoat@HEAD",
    "ecosystem": "npm",
    "source": "lockfile"
  },
  "summary": { "dependencies": 1091, "vulnerable": 130, "vulnerabilities": 187 },
  "dependencies": [
    {
      "name": "express",
      "version": "4.18.0",
      "purl": "pkg:npm/express@4.18.0",
      "ecosystem": "npm",
      "support": {
        "line": "4", "status": "supported", "phase": "Security Support",
        "active_support_until": null, "support_until": null, "basis": "published",
        "source": "https://endoflife.date/express", "retrieved_at": "2026-09-28T09:14:58+00:00"
      }
    },
    {
      "name": "accepts",
      "version": "1.3.8",
      "purl": "pkg:npm/accepts@1.3.8",
      "ecosystem": "npm",
      "support": null
    }
  ],
  "findings": [
    {
      "dependency": {
        "name": "express",
        "version": "4.18.0",
        "purl": "pkg:npm/express@4.18.0",
        "ecosystem": "npm",
        "support": {
          "line": "4", "status": "supported", "phase": "Security Support",
          "active_support_until": null, "support_until": null, "basis": "published",
          "source": "https://endoflife.date/express", "retrieved_at": "2026-09-28T09:14:58+00:00"
        }
      },
      "vulnerabilities": [
        {
          "id": "GHSA-rv95-896h-c2vc",
          "aliases": ["CVE-2024-29041"],
          "summary": "Express.js Open Redirect in malformed URLs",
          "severity": "MODERATE",
          "fixed_version": "4.19.2",
          "url": "https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc"
        }
      ]
    }
  ],
  "truncated": false,
  "unresolved": [],
  "not_assessed": []
}
```

**`target.source` says which question the report answers**, and the answers differ:

| Source | Versions are | Answers |
| ------ | ------------ | ------- |
| `lockfile` | exactly what is installed | *What does this project have?* |
| `manifest` | declared ranges resolved to the newest match | *What would this project get if it installed today?* |
| `package` | what a released version declares | *What does this package pull in?* |
| `image` | what is installed in the image, however it got there | *What does this image contain?* |

This matters when reading a result. A `manifest` scan showing no findings does not mean
the project is safe — it means the *current* versions of its dependencies are clean.
What the project actually runs may well be older, and a `lockfile` scan of the same
project will often find more.

**Completeness is reported, never implied.** `truncated` means a limit stopped the scan
short. `unresolved` names dependencies that could not be resolved at all — a local path,
a git dependency, an unpublished package, a `-r other.txt` that was not followed.
`not_assessed` names what was found but not checked for vulnerabilities, such as an
image's packages from a distribution not handled yet. A scan examines 500 dependencies
by default; raise it with `&limit=3000`.

`generated_at` matters because vulnerability data changes daily: an undated report
cannot be compared against a later one.

### Support status

Each dependency says whether its release line still receives fixes, where its project
publishes a support policy. The data comes from [endoflife.date](https://endoflife.date),
which tracks several hundred products. For npm and PyPI that includes Express, React,
Angular, Vue, Next.js, ESLint, Django and NumPy, among others. Where it has nothing, the
project's own security policy can stand in, as described below. A dependency neither
covers has `"support": null`: no policy is known, which is not the same as no support.
Packages a Linux distribution ships always have `null`: the distribution supports them
for as long as it supports the release, whatever the upstream project does.

| `status` | Means |
| -------- | ----- |
| `active` | The line is in its main period of support |
| `limited` | That period is over, but some fixes still come. `phase` says which, in the project's own words, such as `Security Support` |
| `supported` | Fixes still come, but the project does not distinguish a main period from a later one |
| `eol` | No fixes come at all |

Support is published per release line rather than per version, so `line` names the one
the version belongs to: `4` for Express, `4.2` for Django. Versions are compared with
lines number by number, so `2.10.0` belongs to `2.10` and not to `2.1`.

The status is worked out from the published dates when the report is produced, not when
the data was fetched, so it changes on the day a period of support ends. `retrieved_at`
says how old the data is: it is kept for 30 days, and when endoflife.date cannot be
reached the last copy is used rather than none.

These statuses correspond to the SPDX 3.0 `supportLevel` vocabulary: `active` and
`supported` to `support`, `limited` to `limitedSupport`, and `eol` to `endOfSupport`.

#### From security policies

Most packages are not on endoflife.date, but some say in their `SECURITY.md` which
versions still receive security fixes. Where the worker has a model configured, those
policies are read by Claude and what they state is reported with `"basis": "extracted"`,
`source` pointing at the file. A lifecycle on endoflife.date always takes precedence.

The policy is found through the repository the package's registry names: `SECURITY.md`,
`.github/SECURITY.md` or `docs/SECURITY.md`, and failing those the policy its owner
shares from a `.github` repository. A file that mentions no versions is not sent to the
model. The model only reads what the policy states, either which versions it covers or
a rule relative to the newest release (the latest release, minor or major line). Where a
dependency falls is decided here, not by the model: ranges with npm's own semantics, and
relative rules against the newest version on the registry. `line` is then the range the
policy names, such as `>= 5`, or the line the rule refers to, such as `3.2`. On 15
policies with known answers, 63 of 65 checks pass and no support is invented; see
[`evaluation/`](evaluation/README.md#support-policies).

Reading a policy takes seconds, so it never happens while a report is produced. A
report hands the packages it could not answer to the queue, a worker reads their
policies afterwards, and the next report includes what was found. What was read is kept
under `.cache/policies` for 30 days, including that a project states no supported
versions, so each project is read at most once a month.

Expect it to fill gaps rather than close them: in a sample of 526 npm and PyPI
repositories, about one in ten stated which versions it supports. Only files named
exactly `SECURITY.md` are found; a repository that names it `Security.md` is missed.

## Submitting work instead of waiting

A large tree can take longer to resolve than a caller wants to hold a connection open.
Hand it to a worker instead:

```bash
curl -X POST 'http://127.0.0.1:8010/jobs/npm-package?name=express&version=4.18.0'
```

That returns an identifier immediately. Collect the result from it:

```bash
curl 'http://127.0.0.1:8010/jobs/pkg:npm/express@4.18.0@depth=3'
```

Status is `queued`, `in_progress`, then `complete` with the report attached. Submitting
the same request again while the first is still running returns the same identifier
rather than repeating the work.

To be told when it finishes rather than asking, pass an address to post the report to:

```bash
curl -X POST 'http://127.0.0.1:8010/jobs/npm-package?name=express&version=4.18.0&callback_url=https://example.com/done'
```

## Running it

**Everything together** — API, a worker and Redis, on port 8010:

```bash
docker compose up -d
docker compose up -d --scale worker=4    # more workers
```

**API only**, on port 8000:

```bash
docker build -t sbom-security .
docker run --rm -p 8000:8000 sbom-security
```

Without Redis the scan endpoints work as normal; only the submitted-work endpoints
report themselves unavailable.

**Reading security policies** needs an [Anthropic API](https://console.anthropic.com)
key on the worker. Export it in the shell that starts the stack; `docker-compose.yml`
passes it through without storing it:

```bash
export ANTHROPIC_API_KEY=...
docker compose up -d
```

Without it, support comes from endoflife.date alone. `SBOM_POLICY_MODEL` chooses another
model than the default `claude-opus-5-5`. Reading one policy costs about a cent.

**From source**, for development:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn sbom_security.api:app --reload
pytest && pylint src/ evaluation/
```

Requires Python 3.12 or newer, and outbound network access to reach OSV.dev, deps.dev
and endoflife.date; reading security policies also reaches the npm registry, PyPI,
GitHub and Anthropic's API. Image reports also need [Syft](https://github.com/anchore/syft) on
the `PATH`; the Docker image includes it.

## How it works

```
input  ->  resolve dependencies  ->  normalize to PURL  ->  OSV.dev + endoflife.date  ->  report
```

Matching is done on Package URLs (`pkg:npm/express@4.18.0`) against the OSV schema's
version ranges, which are ecosystem-native and therefore precise. The same Package URL
finds the dependency's support policy on endoflife.date, and both are asked at once.
Where endoflife.date has none, a worker reads the project's security policy after the
report, for the next one to include.

Dependency versions come from lockfiles where one exists, and otherwise from resolved
graphs published by [deps.dev](https://deps.dev), so nothing has to be installed. In a
container image, Syft finds what is actually installed.

Each version's direct dependencies are cached on disk, one file per version, under
`.cache` (override with `SBOM_CACHE_DIR`). Those entries never expire: a published
version cannot change what it depends on, so a package depended on by fifty others is
resolved once rather than fifty times. Support data changes rarely but does change, so
it is kept under `.cache/endoflife` for 30 days, and what security policies state under
`.cache/policies` for as long. Vulnerability data is deliberately not
cached — a package that is clean today can be vulnerable tomorrow.

## Measuring CVE extraction

`evaluation/` holds a dataset of CVE records, each with the structured data a careful
reader should get from it, and a runner that measures any extraction tool against it,
whether a command or a REST endpoint. See [evaluation/README.md](evaluation/README.md).

## Conventions

Commits follow [Conventional Commits](https://www.conventionalcommits.org):
`feat:`, `fix:`, `build:`, `docs:`, `chore:`, `ci:`.

- A `fix:` commit includes the test that failed before the fix and passes after it.
- A `feat:` commit is verified by a full test-suite pass.
- Writing `Resolves #N` in a commit closes that issue when it reaches `main`.

Reused third-party code is recorded in [ATTRIBUTIONS.md](ATTRIBUTIONS.md) at the time
it is added.

## License

Apache-2.0. See [LICENSE](LICENSE).
