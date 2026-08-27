# Multi-stage build producing all four PrivateDNS binaries.
#
# The result is a scratch image: the binaries are static, so there is nothing
# else to ship. No shell, no package manager, no libc — which removes most of
# what a container CVE scanner would otherwise find, and leaves an attacker who
# reaches the container with nothing to run.

# ---------------------------------------------------------------------------
FROM golang:1.24-alpine AS build

# git is needed for the version stamp; ca-certificates is copied out later.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Dependencies first, so a source change does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev

# CGO off is not an optimisation here, it is load-bearing: the SQLite driver is
# pure Go, so the binaries have no dynamic linkage and can run on scratch.
ENV CGO_ENABLED=0 GOOS=linux

RUN set -eux; \
    for c in resolver backend portal admin; do \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o "/out/privatedns-${c}" "./cmd/privatedns-${c}"; \
    done

# Fail the build rather than ship something that will not start.
RUN /out/privatedns-resolver -version

# ---------------------------------------------------------------------------
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=build /out/privatedns-resolver /usr/local/bin/
COPY --from=build /out/privatedns-backend  /usr/local/bin/
COPY --from=build /out/privatedns-portal   /usr/local/bin/
COPY --from=build /out/privatedns-admin    /usr/local/bin/

# 65532 is the conventional "nonroot" uid. Declared numerically because there
# is no /etc/passwd in a scratch image to resolve a name against.
USER 65532:65532

VOLUME ["/var/lib/private-dns"]

# 53 DNS, 443 DoH, 853 DoT, then the three web surfaces.
EXPOSE 53/udp 53/tcp 443 853 8080 8081 8082

ENTRYPOINT ["/usr/local/bin/privatedns-resolver"]
CMD ["-config", "/etc/private-dns/config.yaml"]
