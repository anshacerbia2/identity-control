# Development entry points. `make` with no target lists them.
#
# Every target that needs configuration reads .env, so nothing has to be typed and no command
# here is shell-specific: the same targets work from cmd.exe, PowerShell, and a POSIX shell.
#
# .env is loaded by make and exported to the child process. The service reads only the process
# environment, so nothing about a deployment changes.

SHELL := cmd.exe
.SHELLFLAGS := /c

# -include, not include: fmt, vet, build, arch, and tidy must work in a fresh clone with no
# .env, and in CI, where the environment comes from the workflow.
-include .env
export

# The CI-shaped database. CI's PostgreSQL container is owned by a role named `identity`, which
# is not the local owner, and organization-control had a suite that passed locally and failed
# in CI for exactly that reason: it had hardcoded the owner's name. Reproducing the ownership
# is the point of these.
CI_DATABASE ?= identity_test
CI_OWNER ?= identity
CI_OWNER_PASSWORD ?= identity
CI_DSN ?= postgres://$(CI_OWNER):$(CI_OWNER_PASSWORD)@localhost:5432/$(CI_DATABASE)?sslmode=disable

# The superuser connection, used only to create the owner and the database.
ADMIN_DSN ?= $(TEST_DATABASE_URL)

COVERAGE_FLOOR ?= 80

.DEFAULT_GOAL := help
.PHONY: help env run build fmt vet arch tidy test test-unit test-integration ci-db test-ci \
        coverage gates migrate-status clean

help:
	@echo Targets:
	@echo   make env               copy .env.example to .env (does not overwrite)
	@echo   make gates             everything CI runs: fmt vet build arch tidy test coverage
	@echo   make test-ci           the suite against a CI-shaped database, not the dev one
	@echo   make test-unit         no database needed
	@echo   make test-integration  requires .env and a running PostgreSQL
	@echo   make coverage          the 80 percent floor CI enforces, library packages only
	@echo   make run               needs Keycloak on 127.0.0.1:8081 -- see .env.example
	@echo   make migrate-status    what Atlas thinks the database is at

env:
	@if exist .env (echo .env already exists -- leaving it alone) else (copy .env.example .env >nul && echo Created .env from .env.example)

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

# REQUIRE_INTEGRATION turns a skip into a failure. Without it an unreachable database leaves
# every integration assertion unrun and the suite green, which is indistinguishable from having
# checked something.
test-integration:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	set REQUIRE_INTEGRATION=1&& go test ./internal/... -race -count=1

# The floor CI enforces. CI passes an explicit package list with /cmd/ filtered out, because the
# composition root is verified by the integration steps running the real thing and counting it
# would let an untestable main() depress a number meant to describe code that holds logic.
#
# The list is not optional, and I first wrote this target with `./...` believing it was. A single
# -coverprofile across a package pattern records the untested packages too, at zero: the three
# cmd packages put 100 uncovered statements into the profile and pulled the total from 85% to
# 70.2%, below the floor, while every individual package reported 80% or better. A gate that
# fails for that reason teaches people to raise the floor's exceptions rather than the coverage.
#
# The list comes from make's own $(shell), assigned with `=` so it runs only when this target
# does. Building it inside the recipe needs a variable that survives one line of cmd, and neither
# form works: %PKGS% is expanded while the line is parsed, before the loop that fills it, and
# `cmd /v:on /c "..."` nested inside make's own `cmd /c` loses the quoting and passes a literal
# !PKGS! to go test.
#
# It depends on ci-db and sets REQUIRE_INTEGRATION, because CI measures coverage against a
# migrated database. Run without one, the integration tests skip and the number falls to 70.2%
# against a floor of 80 -- a local failure that says the code is undertested when what happened
# is that a third of the suite never ran.
# No `^` before the pipe: that escape belongs inside a cmd `for /f ('...')`, and $(shell) hands
# the string to cmd unchanged, so the caret reached go list as part of an import path.
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
# Every psql call puts its options BEFORE the connection string and passes it with -d. The
# Windows psql stops parsing options at the first positional argument, so `psql "$DSN" -c "..."`
# warns that -c was ignored, reads an empty stdin, and exits 0 -- a step that silently does
# nothing while reporting success.
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

# ---------------------------------------------------------------------------
# Running it, which needs more than a database
# ---------------------------------------------------------------------------
#
# This service holds the Keycloak Admin credential, so there is no equivalent of
# organization-control's dev token issuer: a local run needs a real Keycloak with the realm
# shape STD-IAM-002 requires. scripts/dev-keycloak.ps1 builds it, and needs Docker or a local
# distribution on 127.0.0.1:8081. Without one, `make test-ci` is how this service is checked.
run:
	@if not exist .env (echo No .env yet. Run: make env && exit 1)
	go run ./cmd/identity-control

migrate-status:
	atlas migrate status --env local

clean:
	go clean -cache -testcache
	@if exist coverage.out del coverage.out
