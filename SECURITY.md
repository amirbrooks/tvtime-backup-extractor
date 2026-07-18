# Security policy

## Supported version

Version 0.1.x is the currently supported alpha line.

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** flow so the report is private. Do not open a
public issue with exploit details.

Never attach a real backup, password, cookie, database, manifest, cache payload, generated table,
report, screenshot, device ID, account ID, or private local path. Reproduce with the repository's
synthetic fixtures or describe the minimum abstract conditions. If a safe reproduction is not
possible, state that without sending the sensitive artifact.

Useful safe information includes the affected version, operating system, Python version, expected
security boundary, observed behavior, and a synthetic proof of concept.

## Scope

Relevant issues include path traversal, unsafe overwrite, credential persistence, unintended export,
sanitization bypass, malicious backup handling, dependency compromise, or CI/release integrity.
Viewing-history recovery limitations and changed TV Time schemas are support or compatibility issues
unless they cross a security boundary.
