# Security Policy

## Supported Versions

Before v1.0.0, only the **latest release** receives security fixes. Older 0.x
releases are not patched retroactively — please upgrade to the newest version.

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/KincaidYang/whois/security/advisories/new)
("Report a vulnerability" on the Security tab).

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal request/config is ideal).
- The version or commit you tested against.

You can expect an initial response within 7 days. Once a fix is released, the
advisory will be published with credit to the reporter (unless you prefer to
remain anonymous).

## Scope notes

This service is designed to be deployed behind a reverse proxy. Rate limiting
exists in-process (`server.rateLimit`), but per-IP limiting and TLS termination are
expected to be handled at the proxy layer.
