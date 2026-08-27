# Security

PrivateDNS sits on the resolution path for every domain its users visit. That
makes a vulnerability here different in kind from one in most software: it can
expose browsing history, let one tenant read another's policy, or redirect
traffic. This document records what has been reviewed, what is deliberately
out of scope, and what has not been done.

To report a vulnerability, see [SECURITY.md](../SECURITY.md). Please do not
open a public issue.

## Threat model

### Who this defends against

| Adversary | Capability | Primary defence |
|---|---|---|
| **Anonymous internet** | Can reach the DNS ports and the customer portal | Unidentified tenants get `REFUSED`; portal is rate-limited and has no unauthenticated mutation |
| **A paying customer** | Holds valid credentials for their own tenant | Per-row authorisation; a customer can only bind their own observed address |
| **A reseller** | Holds operator credentials, competes with other resellers | Row-level isolation; identical 404 for "not yours" and "does not exist" |
| **A network attacker** | Can observe or tamper with traffic in transit | DoT/DoH; releases signed with cosign; installer verifies before installing |
| **A malicious website** | Can make a victim's browser issue requests | DNS rebinding protection; CSRF tokens; strict CSP |

### Who this does not defend against

Stated plainly, because a threat model that claims everything is defended is
useless.

- **A compromised host.** Root on the server reads the database, the
  certificates and every token. Nothing here mitigates that.
- **A malicious operator.** An administrator can read all customer data and
  change routing. The audit log records what they did; it does not prevent it.
- **A compromised upstream resolver.** Answers from upstream are filtered for
  rebinding but otherwise trusted. Run your own recursion.
- **Traffic analysis.** DoT hides the query but not that a connection was made,
  its size, or its timing.
- **A hostile DNS provider for your own zone.** Whoever controls your zone can
  point the tenant hostnames elsewhere and obtain a certificate.

## What was reviewed, and what was found

A structural audit was carried out across the whole codebase. Findings and
their resolution:

### Fixed during review

**API token in a URL** — the dashboard redirected to `/tokens?new=<plaintext>`
after creating a token. A secret in a query string is written to browser
history, sent in the `Referer` header on any outbound link, and recorded
verbatim in nginx access logs and every proxy in between. It is now held
server-side for one redirect, keyed by session, and removed the first time it
is read. Two tests cover it: the value never appears in a redirect, and one
operator's session cannot collect another's.

**No DNS rebinding protection** — a resolver that faithfully returns
`192.168.1.1` for an attacker-controlled name turns every customer's browser
into a way into their own network. Private-space answers are now stripped from
upstream replies, before caching, with an exemption for split-horizon domains.

**Dead code in a security boundary** — two unused functions, one of which
looked like it governed DNSSEC handling. A reader would reasonably assume it
was load-bearing.

### Verified as structurally impossible

Not "we checked carefully" — there is no code path at all:

- **Command injection.** The codebase executes no processes. There is no
  import of `os/exec` anywhere.
- **Path traversal in the web tiers.** No file path is derived from request
  input in the backend, portal or dashboard. Static assets are served from an
  embedded filesystem, not from disk.
- **SQL injection.** Every query uses bound parameters. The one exception is
  `VACUUM INTO` in the backup path, which cannot take a parameter; its
  destination comes from an operator's command line, not a request, and quotes
  are doubled.

### Verified by inspection and test

| Area | How |
|---|---|
| Password storage | argon2id, OWASP baseline parameters, per-password salt |
| Session and token storage | Only hashes stored; a database disclosure yields no usable credential |
| Secret comparison | Constant-time throughout — `subtle.ConstantTimeCompare` and `hmac.Equal` |
| Account enumeration | One message for every login failure; a missing account still pays the argon2 cost |
| Session fixation | A fresh session is created on every login |
| Open redirect | The one caller-supplied redirect is restricted to same-site absolute paths; `//evil.example` is rejected |
| Response splitting | No header value is taken from request input |
| CSRF | Double-submit token on every cookie-authenticated mutation; bearer tokens are exempt by construction |
| XSS | `html/template` throughout, contextual escaping; CSP forbids inline script |
| Tenant isolation | Tested at listing, direct fetch **and** mutation separately |
| Malformed DNS | Fuzzed; a question that is not exactly one valid INET question is refused |
| Malformed TLS | The ClientHello parser is bounds-checked and fuzzed |
| Rate limiting | Per tenant on DNS, per principal on the APIs |
| Privilege separation | Services run unprivileged; only the resolver holds `CAP_NET_BIND_SERVICE` |

## Deployment rules that are not optional

Some things that look like vulnerabilities are misconfigurations. These are the
ones that matter:

**The admin API and dashboard must not be reachable from the internet.** Both
bind `127.0.0.1` by default and log a warning if you change that. Reach the
dashboard over an SSH tunnel:

```bash
ssh -L 8082:127.0.0.1:8082 you@your-server
```

**`open_plain` must stay `false`.** An open resolver is a DNS amplification
vector and the host will be on abuse lists within days.

**`allow_private_destinations` must stay `false` on the proxy tier.** With it
on, anyone who can reach the proxy can point a hostname they control at
`169.254.169.254` and read your cloud credentials.

**Only list a reverse proxy you control in `trusted_proxies`.** Honouring
`X-Forwarded-For` from anywhere lets a client spoof its address, which defeats
login throttling — and on the portal, would let one customer bind another's
address to their tenant.

**DNS ports must not sit behind an HTTP reverse proxy.** Ports 53 and 853 carry
DNS, not HTTP.

## Verifying a release

Every artifact is covered by `SHA256SUMS`, which is signed with cosign using
GitHub's OIDC identity. There is no key to trust — the signature is bound to
the release workflow in this repository.

```bash
cosign verify-blob \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp '^https://github.com/Sakawat-hossain/PrivateDNS/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c --ignore-missing SHA256SUMS
```

`private-dns update` performs both checks automatically when cosign is
installed, and refuses to proceed if the signature does not verify.

## Privacy

The resolver keeps **aggregate counters only** — queries, blocked, overridden,
throttled, per tenant. There is no per-query history, and no code path writes
one. Logs record the parent domain at debug level, never the full name.

This is a deliberate design constraint rather than a default: it is the
strongest privacy claim available, it is cheaper to run, and a database that
does not hold browsing history cannot have it subpoenaed or stolen.

Contributions that add query logging on by default will not be accepted.

## Known gaps

Honest list of what has not been done:

- **The bKash and Nagad payment adapters have never run against a live
  sandbox.** The provider-independent parts — signature verification, replay
  window, amount matching, idempotency — are tested. The endpoints and field
  names are not confirmed.
- **The Dockerfile and Debian packaging have never been built.** They are
  written and reviewed but need a Linux host with Docker and `dpkg-deb`.
- **The installer and updater have never run end-to-end on a live host.** They
  are syntax-checked, shellchecked, and their release-artifact contract is
  asserted in CI.
- **No external penetration test.** Everything above is self-review.
- **No formal audit of the argon2 parameters** against current guidance beyond
  matching the OWASP baseline.
