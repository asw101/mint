# Development

Building mint, and cutting a release.

```sh
just            # list recipes
just check      # gofmt check, vet, and tests
just build      # binary into bin/
just dist       # release binaries for every platform, with checksums
```

`just build` stamps the version from `git describe`, so a binary can say which
release it came from and whether the tree was dirty:

```console
$ mint version
mint v0.6.0
  commit  c2bf8779b920 (clean)
  built   2026-08-08T00:52:55Z
  go      go1.26.5 darwin/arm64
```

A plain `go build` still reports the commit and build time — the toolchain
records those — but cannot name the release.

The tailnet is mocked in tests: `WhoIs` sits behind an `Identifier` interface
and minting behind a `Minter`, so every authorization decision is testable
without joining anything. Keep it that way.

## Releases

Push a `vX.Y.Z` tag. [`.github/workflows/release.yml`](../.github/workflows/release.yml)
builds all four platforms, writes `SHA256SUMS`, attaches the systemd unit, and
publishes the release. It asserts the full asset list before publishing, because
the unit is not build output and a release missing it looks complete.

[`ci.yml`](../.github/workflows/ci.yml) runs gofmt, vet and the race detector on
every push, and cross-compiles every release target.
