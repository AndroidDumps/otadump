# Fixture Corpus

Opaque binary fixtures used by integration tests are consolidated into
`opaque-fixtures.zip` to reduce repository fanout while preserving provenance.

- `MANIFEST.txt` records SHA256, size, and archive path for each packed file.
- `SHA256SUMS` pins the deterministic ZIP blob itself.
- Text provenance files under `tests/fixtures/*` are intentionally retained.
