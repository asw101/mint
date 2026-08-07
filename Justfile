# Build and run tsapp.

set positional-arguments := true

root := justfile_directory()
binary := root / "bin" / "tsapp"

# List available recipes.
default:
    @just --list

# --- Build ---

# Build the binary into bin/.
[group('build')]
build:
    go build -o "{{ binary }}" .

# Install into GOBIN (or GOPATH/bin).
[group('build')]
install:
    go install .

# Remove build output.
[group('build')]
clean:
    rm -rf "{{ root }}/bin"

# --- Check ---

# Run the test suite.
[group('check')]
test *args:
    go test ./... {{ args }}

# Run tests with the race detector and coverage.
[group('check')]
test-race:
    go test -race -cover ./...

# Report files needing gofmt.
[group('check')]
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted="$(gofmt -l .)"
    if [[ -n "$unformatted" ]]; then
        echo "Needs gofmt:" >&2
        echo "$unformatted" >&2
        exit 1
    fi
    echo "All files formatted."

# Rewrite files with gofmt.
[group('check')]
fmt:
    gofmt -w .

# Run vet.
[group('check')]
vet:
    go vet ./...

# Format check, vet, and test — what CI should run.
[group('check')]
check: fmt-check vet test

# --- Daemon ---

# Run the daemon. Needs GH_APP_ID and GH_APP_KEY_FILE.
[group('daemon')]
serve *args: build
    @"{{ binary }}" serve "$@"

# List requests awaiting approval.
[group('daemon')]
pending *args: build
    @"{{ binary }}" pending "$@"

# List current approvals.
[group('daemon')]
approvals *args: build
    @"{{ binary }}" approvals "$@"

# Approve a pending request, e.g. `just approve 7c2a --ttl 720h`.
[group('daemon')]
approve *args: build
    @"{{ binary }}" approve "$@"

# Drop a pending request.
[group('daemon')]
deny *args: build
    @"{{ binary }}" deny "$@"

# Revoke an approval.
[group('daemon')]
revoke *args: build
    @"{{ binary }}" revoke "$@"

# --- Client ---

# Ask the daemon for a token, e.g. `just token --repo widget`.
[group('client')]
token *args: build
    @"{{ binary }}" token "$@"

# Show what the daemon sees this client as.
[group('client')]
whoami *args: build
    @"{{ binary }}" whoami "$@"
