# sbom-security

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

The REST API is not implemented yet. This section will document the endpoints and
example `curl` calls once it lands.

## Docker

Container build and run instructions, including exposed ports, will be added with the
Dockerfile.

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
