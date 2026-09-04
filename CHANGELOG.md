# Changelog

## 1.0.0 — 2026-09-05
- Rebuilt processing pipeline around format detection, decrypt, parse, normalize, URI/JSON generation and validation.
- Removed text/link input from the user interface; input is file-only.
- Removed intermediate processing artifacts from user-facing output.
- Limited advertised input formats to HTTP Injector, NPV Tunnel, HTTP Custom, Dark Tunnel and SSC Custom.
- Preserved the existing SQLite database path and existing core tables; settings migration is additive.
- Added per-format decrypt/URI/JSON/original-file switches and independent global output switches.
- Added parser health checks, version/changelog view, admin access management and recent error views.
