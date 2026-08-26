# sbom-security

[![tests](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml/badge.svg)](https://github.com/RedHatResearch/sbom-security/actions/workflows/tests.yml)

Report the dependencies of an npm package or repository, together with the known
vulnerabilities affecting them.

Given a package (`express@4.18.0`) or a repository containing a `package-lock.json`,
the tool resolves all dependencies at their exact versions, matches them against
[OSV.dev](https://osv.dev) using Package URLs, and returns a JSON report.

**Status:** early development. Milestone 1 covers npm, a REST API, and a JSON report.

## How it works

```
input  ->  resolve dependencies  ->  normalize to PURL  ->  match against OSV.dev  ->  report
```

The two input shapes differ in one important way:

- A **package** carries its own version.
- A **repository** has no version of its own. Its dependencies are read from the
  lockfile, which already pins the complete resolved set.

Matching is done on Package URLs (`pkg:npm/express@4.18.0`) against the OSV schema's
version ranges, which are ecosystem-native and therefore precise.

## Requirements

- Python 3.12 or newer

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the tests and the linter:

```bash
pytest
pylint src/
```

## Usage

Start the service:

```bash
uvicorn sbom_security.api:app --reload
```

Report on a repository by sending its lockfile:

```bash
curl -X POST http://127.0.0.1:8000/reports/npm-lockfile \
  -H 'Content-Type: application/json' \
  --data-binary @package-lock.json
```

The response lists every dependency, and the vulnerabilities affecting those that are
known to be affected:

```json
{
  "target": "example-project",
  "dependencies": [
    { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0" }
  ],
  "findings": [
    {
      "dependency": { "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0" },
      "vulnerabilities": [
        {
          "id": "GHSA-rv95-896h-c2vc",
          "aliases": ["CVE-2024-29041"],
          "summary": "Express.js Open Redirect in malformed URLs",
          "severity": "MODERATE",
          "fixed_version": "4.19.2"
        }
      ]
    }
  ]
}
```

Or name a public GitHub repository and let the service read its lockfile:

```bash
curl 'http://127.0.0.1:8000/reports/github?owner=OWASP&repo=NodeGoat'
```

Only `package-lock.json` is fetched — nothing is cloned, no package manager runs, and
no code from the repository is executed. The ref defaults to the repository's default
branch, whatever it is called.

Large projects pin thousands of packages, and every distinct advisory costs another
request to the vulnerability source, so a report examines at most 500 dependencies by
default. Raise it with `&limit=2000`. A report that hit the limit comes back with
`"truncated": true`, so a partial result is never mistaken for a clean one.

Or report on a package without any lockfile at all:

```bash
curl 'http://127.0.0.1:8000/reports/npm-package?name=express&version=4.18.0&depth=3'
```

Dependency versions come from resolved graphs published by [deps.dev](https://deps.dev),
so nothing has to be installed. `depth` controls how many levels are walked — one gives
direct dependencies only. A walk stopped by the depth limit is marked `"truncated": true`.

Each version's direct dependencies are cached on disk, one file per version, under
`.cache` (override with `SBOM_CACHE_DIR`). Those entries never expire: a published
version cannot change what it depends on, so a package depended on by fifty others is
resolved once rather than fifty times.

Interactive API documentation is served at `http://127.0.0.1:8000/docs`.

A repository is submitted as its lockfile rather than as a URL to clone: the lockfile
is the authority on what is installed, and this avoids giving the service network
access to arbitrary repositories.

## Docker

```bash
docker build -t sbom-security .
docker run --rm -p 8000:8000 sbom-security
```

The service listens on port 8000 inside the container, published here as 8000 on the
host, so the `curl` calls above work unchanged. Outbound network access is required to
reach the OSV.dev API.

Check that it started:

```bash
curl http://127.0.0.1:8000/health
```

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
