# Contributing to PrivateDNS

Thanks for taking an interest. This document covers what you need to know
before opening a pull request.

## Before you start

For anything larger than a bug fix, **open an issue first**. It saves you
building something that does not fit, and saves everyone a difficult review.

Security problems do not go here — see [SECURITY.md](SECURITY.md).

## Development setup

You need Go 1.24 or newer. There are no other build dependencies: the SQLite
driver is pure Go, so nothing needs cgo or a C toolchain.

```bash
git clone https://github.com/Sakawat-hossain/PrivateDNS.git
cd PrivateDNS
make test
```

`make help` lists the available targets.

## What a pull request needs

- `make check` passes — that is `gofmt`, `go vet` and the full test suite
- New behaviour comes with tests
- Commit messages explain **why**, not just what
- No secrets, no real domains, no customer data, not even in test fixtures

Use `example.com` and the documentation address ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) in tests. Never a real host.

## Things that will be rejected

- **Query logging on by default.** Aggregate counters are the intended level of
  observability. Anything that records a customer's full query history must be
  opt-in and clearly documented.
- **Hardcoded environment.** No domains, IPs, paths, tokens or customer
  identifiers in source. It all belongs in configuration.
- **Weakening tenant isolation.** One tenant must never be able to observe or
  affect another's policy.
- **Unauthenticated administrative endpoints.** Every mutating route requires
  authentication and authorisation, without exception.

## Code style

Standard Go. `gofmt` decides formatting arguments, so there are none.

Comments should explain reasoning that is not evident from the code. A comment
restating what the next line does is noise; a comment explaining why an IPv4
override suppresses AAAA answers is worth its space.

## Licence

Contributions are licensed under AGPL-3.0, the same as the project. By opening
a pull request you confirm you have the right to contribute the code under that
licence.
