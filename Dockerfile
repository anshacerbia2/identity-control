# syntax=docker/dockerfile:1
#
# Two images from one build:
#
#   service   the Identity Control Service, on distroless static as a non-root user
#   migrate   the Control Database pipeline and the bootstrap ceremony, on the Postgres image,
#             because the pipeline needs psql and the ceremony runs once from an operator's shell
#
# Every base is pinned by digest (SAD-001 §7.6). The tag each digest was resolved from is beside it.

# golang:1.26.9-alpine
FROM golang@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS build
WORKDIR /src
COPY go.mod go.sum ./
# Overridable for networks that intercept proxy.golang.org: pass GOPROXY=direct as a build arg, and
# modules are fetched from their origins, which needs git -- installed in this stage only, and only
# in that mode. Integrity does not depend on the proxy either way: go.sum and the checksum database
# (GOSUMDB) verify every module. The default is Go's own.
ARG GOPROXY=https://proxy.golang.org,direct
RUN if [ "$GOPROXY" = "direct" ]; then apk add --no-cache git; fi && go mod download
COPY . .
# CGO off, so the binaries run on distroless static and on the Postgres image alike.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/identity-control ./cmd/identity-migrate ./cmd/identity-bootstrap ./cmd/identity-provider-bootstrap ./cmd/identity-signing-key

# arigaio/atlas:1.3.9, resolved from Docker Hub on 2026-11-10. 1.3.4 carried andybalholm/brotli v1.2.0
# (GO-2026-6888, Critical, in the CISA KEV catalogue) and klauspost/compress v1.18.7 (GO-2026-6865,
# High), which the gate found from 2026-11-05 (TDD-identity-control-001 §The Migrate Image and Its
# Exceptions).
FROM arigaio/atlas@sha256:ce36679f6e253ff13ec0c9cb07787c8c7b02934ad9b76c969977570391d696a8 AS atlas

# postgres:17.11-alpine3.24, resolved from Docker Hub on 2026-11-10 (rebuilt upstream 2026-11-06) --
# the same image the Control Database runs, so psql matches the server.
FROM postgres@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac AS migrate
COPY --from=atlas /atlas /usr/local/bin/atlas
# Atlas checks for a newer release over HTTPS around every command unless ATLAS_NO_UPDATE_NOTIFIER is
# set, and may send anonymous telemetry unless ATLAS_NO_ANON_TELEMETRY is true. With both off it
# connects to nothing but the database. scripts/atlas-execute-path.sh proves it on every scan, so a
# new advisory in this file is decided against current evidence (TDD-identity-control-001 §The
# Migrate Image and Its Exceptions).
ENV ATLAS_NO_UPDATE_NOTIFIER=true \
    ATLAS_NO_ANON_TELEMETRY=true
COPY --from=build /out/identity-migrate /out/identity-bootstrap /out/identity-provider-bootstrap /out/identity-signing-key /usr/local/bin/
WORKDIR /work
COPY atlas.hcl schema.hcl ./
COPY migrations ./migrations
COPY deploy/dev/migrate.sh /usr/local/bin/identity-dev-migrate
RUN chmod 0755 /usr/local/bin/identity-dev-migrate
# The pinned base may lag Alpine's fixes (STD-GLB-009 §Container Images rule 10). These constraints
# fail the build if no repository can meet them: zlib 1.4-r0 fixes CVE-2026-4738 (Critical) and
# CVE-2026-85091, musl 1.2.6-r3 fixes CVE-2026-107891 (High). Remove a constraint once the postgres
# pin carries the fix.
# 2026-11-11: libxslt 1.1.43-r4 fixes CVE-2026-125350 (in the KEV), CVE-2026-87636 and CVE-2026-9947;
# krb5-libs 1.22.3-r0 fixes nine High findings, CVE-2026-112314 among them.
RUN apk add --no-cache 'zlib>=1.4-r0' 'musl>=1.2.6-r3' 'musl-utils>=1.2.6-r3' \
      'libxslt>=1.1.43-r4' 'krb5-libs>=1.22.3-r0'
# The image's own unprivileged user. The pipeline connects to the database as its superuser over
# the network; it needs no privilege in this container.
USER postgres
ENTRYPOINT ["identity-dev-migrate"]

# gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS service
COPY --from=build /out/identity-control /identity-control
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/identity-control"]
