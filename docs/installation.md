# Installation

Three ways, in order of preference.

## 1. Installer script (recommended today)

```bash
curl -fsSLO https://github.com/Sakawat-hossain/PrivateDNS/releases/latest/download/install.sh
curl -fsSLO https://github.com/Sakawat-hossain/PrivateDNS/releases/latest/download/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh
```

> **Why not `curl … | sudo bash`?**
>
> Piping a URL into a root shell hands root to whatever the server returns,
> with no opportunity to read it first and no protection if the download is
> tampered with. For a product whose entire pitch is trust, that is the wrong
> first impression. The two extra lines above are the whole difference.

The installer checks the OS and architecture, warns about ports already in
use, creates the service account and directories, verifies every binary
against the published checksums, generates a config with a random admin token,
installs the systemd units, fetches a blocklist, starts the resolver, and
prints what remains.

It is safe to re-run: an existing installation is upgraded and **configuration
files that already exist are never overwritten**.

## 2. Debian package — not yet published

> **There is no `.deb` in the current release.** The packaging is written and
> reviewed but has never been built, so it is not published rather than shipped
> untested. It arrives with the first CI run.

When it does, a package manager is the better path: it gives upgrade, rollback,
integrity checking and clean removal without any of it being reimplemented in a
shell script. `apt remove` will keep your data; only `apt purge` deletes it.

## 3. Docker — not yet published

> **No image has been built or pushed.** `Dockerfile` and `docker-compose.yml`
> are in the repository and can be built locally, but nothing is published to a
> registry yet.


```bash
git clone https://github.com/Sakawat-hossain/PrivateDNS.git
cd PrivateDNS
cp .env.example .env
docker compose up -d          # builds locally; nothing is pulled
```

All four services share one image and one volume, and must run on the same
host — the policy database is a file, not a network service.

## After installing

Installation does not finish the job. Three things remain:

### 1. Set your domain

Edit `base_domain` in `/etc/private-dns/config.yaml` and in the `.yaml` files
beside it.

### 2. Point DNS at the host

| Type | Name | Value |
|---|---|---|
| A | `dns` | your server's IP |
| A | `*.dns` | your server's IP |

> **On Cloudflare, both records must be DNS-only (grey cloud).** The
> orange-cloud proxy carries HTTP only — it cannot pass port 53 or 853, and
> enabling it breaks the service in a way that looks exactly like a firewall
> problem.

### 3. Issue a wildcard certificate

Per-tenant hostnames need a wildcard, and a wildcard can only be issued over
the **DNS-01** challenge. HTTP-01 cannot produce one.

```bash
sudo sh -c 'printf "CF_DNS_API_TOKEN=your_token\n" > /etc/private-dns/cloudflare.env'
sudo chmod 600 /etc/private-dns/cloudflare.env
sudo ACME_EMAIL=you@example.com BASE_DOMAIN=dns.yourdomain.com privatedns-issue-cert run
sudo systemctl restart privatedns-resolver
```

The token needs one permission: DNS edit, scoped to your zone. It never goes
in the repository or in `.env`.

### Then start the rest

```bash
sudo systemctl enable --now privatedns-backend privatedns-portal privatedns-admin
private-dns status
```

## Port 53 is often taken

Most Ubuntu installs run `systemd-resolved` on `:53`:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

## Managing it

```bash
private-dns status              # what is running, and whether it is healthy
private-dns logs [component]    # follow the logs
private-dns update              # upgrade, with rollback if it fails
private-dns backup              # verified snapshot now
private-dns backups             # what is on this host
private-dns restore <file>      # restore a database backup
private-dns uninstall           # remove, keeping data
```

## Verification status

Honest note on what has and has not been exercised:

| | Status |
|---|---|
| Go binaries, all four | built and tested, amd64 and arm64 |
| Backup and restore | tested, including WAL correctness |
| Shell scripts | syntax-checked; **not run end-to-end on a live host** |
| Dockerfile, compose | written; **not built** |
| Debian packaging | written; **not built** |

The container and package builds need a Linux host with Docker and `dpkg-deb`.
Expect to iterate on them the first time.
