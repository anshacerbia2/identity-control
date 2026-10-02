# Development entry points. `make` with no target lists them.
#
# Every target that needs configuration reads .env, so no environment has to be typed and no
# command here is shell-specific: the same targets work from cmd.exe, PowerShell and cmder. The
# names match organization-control's and foundation-reference's, so one habit runs all three.
#
# .env is loaded by make and exported to the child process. The service reads only the process
# environment and validates every setting in internal/config, so nothing about a deployment
# changes and a wrong value is refused at startup with its name.

SHELL := cmd.exe
.SHELLFLAGS := /c

# -include, not include: fmt, vet, build, arch and tidy must work in a fresh clone with no .env,
# and in CI, where the environment comes from the workflow.
-include .env
export

# The CI-shaped database. CI's PostgreSQL container is owned by a role named `identity`, which is
# not the local owner, and a suite that hardcodes the owner passes locally and fails there.
# Reproducing the ownership is the point of these.
CI_DATABASE ?= identity_test
CI_OWNER ?= identity
CI_OWNER_PASSWORD ?= identity
CI_DSN ?= postgres://$(CI_OWNER):$(CI_OWNER_PASSWORD)@localhost:5432/$(CI_DATABASE)?sslmode=disable

# The superuser connection, used only to create the owner and the database. Taken from .env so
# there is one place holding local credentials.
ADMIN_DSN ?= $(TEST_DATABASE_URL)

COVERAGE_FLOOR ?= 80

.DEFAULT_GOAL := help
.PHONY: help env run migrate bootstrap provider-bootstrap build fmt vet arch tidy test test-unit test-integration \
        ci-db test-ci coverage gates migrate-status clean

help:
	@echo Targets:
	@echo   make env               copy .env.example to .env (does not overwrite)
	@echo   make migrate           roles and platform schema, Atlas, privileges, against IDENTITY_MIGRATION_DATABASE_URL
	@echo   make run               the service on IDENTITY_LISTEN_ADDRESS -- needs a Keycloak, see .env.example
	@echo   make bootstrap OPERATOR=... REASON=... USERNAME=... [RESUME=1]   the one-time ceremony
	@echo   make provider-bootstrap  the provider authority projection from Organization Control's snapshot
	@echo   make gates             everything CI runs: fmt vet build arch tidy test coverage
	@echo   make test-ci           the suite against a CI-shaped database, not the dev one
	@echo   make test-unit         no database needed
	@echo   make test-integration  requires .env and a running PostgreSQL
	@echo   make coverage          the 80 percent floor CI enforces, library packages only
	@echo   make migrate-status    what Atlas thinks the database is at

# Not a copy that overwrites: .env holds working local credentials, and clobbering it from a
# template is the kind of loss noticed one debugging hour later.
env:
	@if exist .env (echo .env already exists -- leaving it alone) else (copy .env.example .env >nul && echo Created .env from .env.example)

# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------

# The three stages CI runs, in its order. DATABASE_URL is what atlas.hcl reads; it is set from
# the migration DSN for this target alone, so .env needs one variable rather than two.
migrate:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	go run ./cmd/identity-migrate -stage=pre
	@set "DATABASE_URL=$(IDENTITY_MIGRATION_DATABASE_URL)"&& atlas migrate apply --env local
	go run ./cmd/identity-migrate -stage=post

# This service holds the Keycloak Admin credential, so a local run needs a real Keycloak with the
# realm shape STD-IAM-002 requires. Without one, `make test-ci` is how this service is checked.
run:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	go run ./cmd/identity-control

# The ceremony of ADR-IAM-001 §5.11, once per realm. Every value is recorded immutably, so each is
# required rather than defaulted. RESUME=1 completes an interrupted ceremony under the recorded
# operator, which is also how an estate whose ceremony ran before rule 5 registers its resource.
bootstrap:
	@if "$(OPERATOR)"=="" (echo Usage: make bootstrap OPERATOR=name REASON=why USERNAME=user [EMAIL=address] && exit 1)
	@if "$(REASON)"=="" (echo REASON is required: it is recorded immutably && exit 1)
	@if "$(USERNAME)"=="" (echo USERNAME is required: the first Principal's username && exit 1)
	go run ./cmd/identity-bootstrap -operator "$(OPERATOR)" -reason "$(REASON)" -username "$(USERNAME)" $(if $(EMAIL),-email "$(EMAIL)",) $(if $(RESUME),-resume "$(OPERATOR)",)

# TDD-identity-control-006 §Bootstrap. Needs Organization Control running with this service
# registered as its identity-control consumer, and IDENTITY_ORGANIZATION_BASE_URL with the workload
# client in .env. Safe to rerun: the snapshot is applied by version.
provider-bootstrap:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	@if "$(IDENTITY_ORGANIZATION_BASE_URL)"=="" (echo IDENTITY_ORGANIZATION_BASE_URL is unset in .env -- see .env.example && exit 1)
	go run ./cmd/identity-provider-bootstrap

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

build:
	go build ./...

# gofmt -l reports by printing names and exits 0 either way, so the check is whether it printed
# anything. findstr is the test rather than `for /f`, which exits 1 over an empty file and would
# fail this gate on a clean tree while naming no file.
fmt:
	@gofmt -l . > .fmt.tmp
	@findstr /r /c:"." .fmt.tmp >nul && (echo Not gofmt-clean: && type .fmt.tmp && del .fmt.tmp && exit 1) || (del .fmt.tmp && echo gofmt clean)

vet:
	go vet ./...

arch:
	go run github.com/anshacerbia2/foundation-platform/tools/archcheck

tidy:
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo go.mod or go.sum changed -- commit the result && exit 1)

test:
	go test ./... -race -count=1

test-unit:
	go test ./... -race -short

# REQUIRE_INTEGRATION turns a skip into a failure. Without it an unreachable database leaves every
# integration assertion unrun and the suite green, which is indistinguishable from having checked
# something.
test-integration:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	set REQUIRE_INTEGRATION=1&& go test ./internal/... -race -count=1

# The floor CI enforces, over the packages CI measures: cmd/ is excluded, because the composition
# root is verified by running it, and counting it would let an untestable main() depress a number
# meant to describe code that holds logic.
#
# A single -coverprofile across ./... would record the cmd packages at zero and pull the total
# below the floor while every package meets it, so the list is built explicitly. It comes from
# make's $(shell), assigned with `=` so it runs only when this target does: a variable built inside
# the recipe does not survive cmd's line-at-a-time parsing.
#
# It depends on ci-db, because CI measures coverage against a migrated database; without one the
# integration tests skip and the number reads as undertested when a third of the suite never ran.
COVERED_PACKAGES = $(shell go list ./... | findstr /v /c:/cmd/)

coverage: ci-db
	@set "TEST_DATABASE_URL=$(CI_DSN)"&& set "REQUIRE_INTEGRATION=1"&& go test $(COVERED_PACKAGES) -count=1 -covermode=atomic -coverprofile=coverage.out
	@go tool cover -func=coverage.out | findstr /r /c:"^total:"
	@for /f "tokens=3" %%t in ('go tool cover -func^=coverage.out ^| findstr /r /c:"^total:"') do @(for /f "tokens=1 delims=." %%w in ("%%t") do @if %%w LSS $(COVERAGE_FLOOR) (echo coverage %%t is BELOW the $(COVERAGE_FLOOR) percent floor && exit 1) else (echo coverage %%t meets the $(COVERAGE_FLOOR) percent floor))

gates: fmt vet build arch tidy test coverage
	@echo All gates passed.

# ---------------------------------------------------------------------------
# Reproducing CI's database locally
# ---------------------------------------------------------------------------
#
# Every psql call puts its options BEFORE the connection string and passes it with -d. The Windows
# psql stops parsing options at the first positional argument, so `psql "$DSN" -c "..."` warns that
# -c was ignored, reads an empty stdin, and exits 0: a step that silently does nothing while
# reporting success.
#
# CI_DATABASE is dropped and recreated on every run, the way a fresh container is. It is a
# dedicated test database and must never be pointed at anything else.
ci-db:
	@if "$(ADMIN_DSN)"=="" (echo No TEST_DATABASE_URL. Run: make env && exit 1)
	@echo Creating $(CI_OWNER) and $(CI_DATABASE) the way the CI container does...
	@psql -v ON_ERROR_STOP=1 -q -c "DO $$$$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$(CI_OWNER)') THEN CREATE ROLE $(CI_OWNER) LOGIN SUPERUSER PASSWORD '$(CI_OWNER_PASSWORD)'; ELSE ALTER ROLE $(CI_OWNER) LOGIN SUPERUSER PASSWORD '$(CI_OWNER_PASSWORD)'; END IF; END $$$$;" -d "$(ADMIN_DSN)"
	@psql -v ON_ERROR_STOP=1 -q -c "DROP DATABASE IF EXISTS $(CI_DATABASE);" -c "CREATE DATABASE $(CI_DATABASE) OWNER $(CI_OWNER);" -d "$(ADMIN_DSN)"
	@set "IDENTITY_MIGRATION_DATABASE_URL=$(CI_DSN)"&& go run ./cmd/identity-migrate -stage=pre
# `dir /b /on` rather than a plain wildcard: migrations apply in filename order, and cmd's
# `for %%f in (*.sql)` walks directory order, which is not the same thing and fails as a
# missing-column error in whichever migration ran too early.
	@for /f "delims=" %%f in ('dir /b /on migrations\*.sql') do @(psql -v ON_ERROR_STOP=1 -q -f migrations\%%f -d "$(CI_DSN)" && echo applied %%f) || exit 1
	@set "IDENTITY_MIGRATION_DATABASE_URL=$(CI_DSN)"&& go run ./cmd/identity-migrate -stage=post
	@echo $(CI_DATABASE) is ready, owned by $(CI_OWNER).

test-ci: ci-db
	@set "TEST_DATABASE_URL=$(CI_DSN)"&& set "REQUIRE_INTEGRATION=1"&& go test ./... -race -count=1

migrate-status:
	@set "DATABASE_URL=$(IDENTITY_MIGRATION_DATABASE_URL)"&& atlas migrate status --env local

clean:
	go clean -cache -testcache
	@if exist coverage.out del coverage.out
