# syntax=docker/dockerfile:1
#
# Two images from one build:
#
#   service   the Identity Control Service, on distroless static as a non-root user
#   migrate   the Control Database pipeline and the bootstrap ceremony, on the Postgres image,
#             because the pipeline needs psql and the ceremony runs once from an operator's shell
#
# Every base is pinned by digest (SAD-001 §7.6). The tag each digest was resolved from is beside it.

# golang:1.26.8-alpine
FROM golang@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off, so the binaries run on distroless static and on the Postgres image alike.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/identity-control ./cmd/identity-migrate ./cmd/identity-bootstrap

# arigaio/atlas:1.3.3
FROM arigaio/atlas@sha256:07f3f92fa46e684ed789d5ef344a25494a4fa6844ef1ea1fa4e138522c2c37ac AS atlas

# postgres:17.11-alpine -- the same image the Control Database runs, so psql matches the server.
FROM postgres@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24 AS migrate
COPY --from=atlas /atlas /usr/local/bin/atlas
COPY --from=build /out/identity-migrate /out/identity-bootstrap /usr/local/bin/
WORKDIR /work
COPY atlas.hcl schema.hcl ./
COPY migrations ./migrations
COPY deploy/dev/migrate.sh /usr/local/bin/identity-dev-migrate
RUN chmod 0755 /usr/local/bin/identity-dev-migrate
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
