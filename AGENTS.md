# Testing

- Run `python -m unittest discover -s tests -v` for every change.
- Unit tests must not use the network or the user's real artifact cache.
- Run `python tests/artifact_smoke.py` when changing artifact acquisition or process invocation.
