# Security Policy

PrivateDNS sits on the resolution path for every domain its users visit. A
vulnerability here is not an inconvenience — it can expose browsing history,
let one tenant read another's policy, or redirect traffic. Please treat
findings accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/Sakawat-hossain/PrivateDNS/security/advisories/new)

That channel is private to the maintainers until a fix ships.

Please include:

- What the issue is and where in the code it lives
- How to reproduce it — a minimal case is worth more than a long description
- What an attacker gains
- Any suggested fix, if you have one

You should get an acknowledgement within **72 hours** and an assessment within
**7 days**. If a report is valid we will agree a disclosure timeline with you;
the default is public disclosure once a fix is released, crediting you unless
you would rather stay anonymous.

## Supported versions

| Version | Supported |
|---|---|
| `main` | yes |
| tagged releases | latest minor only |

This project is pre-1.0. Until then, only the most recent release receives
security fixes.

## Scope

In scope:

- The resolver: DoT, DoH and plain DNS handling, packet parsing, caching
- Tenant identification and isolation
- The policy engine: allowlist, blocklist, overrides
- The admin and provisioning API: authentication, authorisation, injection
- Deployment scripts and systemd units, where they affect privilege
- TLS configuration and certificate handling

Out of scope:

- Denial of service through sheer volume against a test instance you control
- Findings that require an attacker to already hold the admin token
- Vulnerabilities in dependencies that have no exploitable path here — report
  those upstream, though we would still like to know
- Social engineering, physical attacks, or issues in third-party hosting

## Deployment expectations

Some behaviour that looks like a vulnerability is a misconfiguration. Before
reporting, check the deployment against these:

- **The admin API must never be reachable from the internet.** It binds to
  `127.0.0.1` by default. Exposing it publicly is a configuration error, not a
  bug in the software.
- **`open_plain` must stay `false`** unless the operator genuinely wants an open
  resolver. An open resolver is a DNS amplification vector and will get the
  host onto abuse lists.
- **DNS ports must not sit behind an HTTP reverse proxy.** Port 53 and 853
  carry DNS, not HTTP. Only the web interface belongs behind Nginx.

## What this project will not do

We will not add telemetry that reports customer queries anywhere, and we will
not accept contributions that log full query history by default. Aggregate
counters are the intended level of observability.
