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
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/identity-control ./cmd/identity-migrate ./cmd/identity-bootstrap ./cmd/identity-provider-bootstrap

# arigaio/atlas:1.3.3
FROM arigaio/atlas@sha256:07f3f92fa46e684ed789d5ef344a25494a4fa6844ef1ea1fa4e138522c2c37ac AS atlas

# postgres:17.11-alpine -- the same image the Control Database runs, so psql matches the server.
FROM postgres@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 AS migrate
COPY --from=atlas /atlas /usr/local/bin/atlas
# Atlas checks for a newer release over HTTPS around every command unless ATLAS_NO_UPDATE_NOTIFIER is
# set, and may send anonymous telemetry unless ATLAS_NO_ANON_TELEMETRY is true. With both off it
# connects to nothing but the database, which the not_affected statements for this file in
# .grype.yaml rest on: removing either line voids them (TDD-identity-control-001 §The Migrate Image
# and Its Exceptions; scripts/atlas-execute-path.sh proves it on every scan).
ENV ATLAS_NO_UPDATE_NOTIFIER=true \
    ATLAS_NO_ANON_TELEMETRY=true
COPY --from=build /out/identity-migrate /out/identity-bootstrap /out/identity-provider-bootstrap /usr/local/bin/
WORKDIR /work
COPY atlas.hcl schema.hcl ./
COPY migrations ./migrations
COPY deploy/dev/migrate.sh /usr/local/bin/identity-dev-migrate
RUN chmod 0755 /usr/local/bin/identity-dev-migrate
# CVE-2026-85091: the pinned base carries zlib 1.3.2-r0, and Alpine ships the fix as 1.3.2-r1
# (STD-GLB-009 §Container Images rule 10). The constraint fails the build if no repository can meet
# it. Remove this line when the postgres pin moves to an image that carries the fix.
RUN apk add --no-cache 'zlib>=1.3.2-r1'
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
