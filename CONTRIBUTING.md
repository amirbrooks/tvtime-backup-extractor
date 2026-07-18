# Contributing

Contributions are welcome while preserving the project's privacy boundary.

## Non-negotiable data rule

Use synthetic fixtures only. Do not commit, paste, attach, or quote any real backup, recovered file,
viewing title/history, timestamp, stable ID, hash, hostname, username, path, profile, URL, cookie,
database, manifest, password, token, or screenshot. A value being redacted or from your own account
does not make the surrounding artifact safe.

## Development setup

```text
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --only-binary=:all: --requirement requirements.txt
python -m pip install --only-binary=:all: --requirement requirements-dev.txt
python -m pip install --no-deps .
```

Do not add or upgrade dependencies casually. Pin reviewed versions and check relevant advisories.

## Required checks

```text
python -m ruff check .
python -m ruff format --check .
python -m unittest discover -s tests -v
python -m build --no-isolation
```

Also run `git diff --check` and inspect the complete staged file list. Python equivalents replace the
TypeScript-only `tsc`, JavaScript lint, and JavaScript build gates because this repository contains no
TypeScript or JavaScript package.

Use focused changes and Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, `refactor:`,
and `test:`. Update user instructions when commands or output change. Report security issues through
[SECURITY.md](SECURITY.md), not a public pull request.
