# Native ZUCCHINI artifact architecture

Status: active for Linux x86-64 GNU builds.

## Overview

`otadump` links a prebuilt `libotadump_zucchini.a` archive for Linux x86-64 GNU
targets and keeps all other targets on the pure-Rust delta stack without the
native bridge.

The artifact is pinned by:

- `native/zucchini/ARTIFACT_BUNDLE_LOCK.json` (immutable commit URL + archive digest)
- `native/zucchini/ARTIFACT_LOCK.sha256` (per-file digest lock inside the extracted tree)

`build.rs` invokes `scripts/fetch-native-artifact.py` unless
`OTADUMP_NATIVE_DIR` is set.

## Security and integrity guarantees

The fetch helper enforces:

1. HTTPS-only URL policy.
2. Exact host policy: `raw.githubusercontent.com`.
3. Exact immutable path policy:
   `/AndroidDumps/otadump/<commit>/native/artifacts/zucchini/zucchini-linux-x86_64-gnu.tar.gz`.
4. Download timeout and max-size bounds.
5. Archive digest verification before extraction.
6. Tar safety checks: no traversal, no symlinks/hardlinks, files/dirs only.
7. Strict extracted-tree verification: no extra files/directories outside the
   checksum lock's expected structure.

## Concurrency model

Concurrent builds sharing `OTADUMP_NATIVE_CACHE` coordinate through a fetch lock
keyed by bundle digest.

- Only one process writes the cached archive at a time.
- Each process stages extraction into a unique temp directory.
- Publication uses atomic rename; one contender wins.
- Losers verify the published tree and continue.

This avoids partial publication and keeps cache/output deterministic under
parallel runners.

## Offline and preseed behavior

- `OTADUMP_NATIVE_OFFLINE=1`: network disabled; build requires cached or
  preseeded artifact.
- `OTADUMP_NATIVE_PRESEED=/path/to/archive.tar.gz`: copies the archive into the
  cache before checksum verification.
- `OTADUMP_NATIVE_PRESEED=/path/to/tree`: verifies and publishes a fully
  materialized extracted tree.

## Test coverage

`tests/native_artifact_fetch_test.py` covers:

- parallel fetch/publish contention
- URL policy rejections
- strict extra-file rejection
- checksum tamper rejection
- traversal rejection
- offline-with-empty-cache rejection
