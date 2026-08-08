# Build and run tsapp.

set positional-arguments := true

root := justfile_directory()
binary := root / "bin" / "tsapp"

# Stamped into the binary so `tsapp version` can name the release it came from.
# Empty outside a checkout, where the toolchain's VCS stamping takes over.
version := `git describe --tags --match 'tsapp/v*' --dirty 2>/dev/null || echo ""`
ldflags := "-s -w -X main.version=" + version

# List available recipes.
default:
    @just --list

# --- Build ---

# Build the binary into bin/.
[group('build')]
build:
    go build -trimpath -ldflags="{{ ldflags }}" -o "{{ binary }}" .

# Build release binaries for every supported platform, with checksums.
[group('build')]
dist:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf "{{ root }}/dist" && mkdir -p "{{ root }}/dist"
    for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do
        os="${target%/*}"; arch="${target#*/}"
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
            -ldflags="{{ ldflags }}" \
            -o "{{ root }}/dist/tsapp_${os}_${arch}" .
        echo "built ${os}/${arch}"
    done
    cd "{{ root }}/dist" && sha256sum tsapp_* > SHA256SUMS
    ls -l "{{ root }}/dist"

# Install into GOBIN (or GOPATH/bin).
[group('build')]
install:
    go install -trimpath -ldflags="{{ ldflags }}" .

# Remove build output.
[group('build')]
clean:
    rm -rf "{{ root }}/bin" "{{ root }}/dist"

# Print the version this checkout would stamp.
[group('build')]
version:
    @echo "{{ if version == "" { "(unstamped; toolchain VCS info only)" } else { version } }}"

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
