# Changelog

All notable changes to this project are documented in this file.

## [1.1.0] - 2026-08-27

### Added

- Public-target validation with private, loopback, link-local, metadata, and reserved address blocking.
- Per-client scan rate limiting and a health-check endpoint.
- Unit tests for target validation, certificate thresholds, and Nmap output parsing.
- GitHub Actions CI for type-checking, tests, application builds, and Docker builds.
- Dependabot configuration and deployment environment documentation.

### Changed

- Replaced shell-based Nmap execution with argument-safe `execFile` calls.
- Replaced HTTP `HEAD` checks with direct TLS handshakes, allowing non-HTTP TLS services.
- Consolidated the downloadable and displayed NSE source into one canonical file.
- Hardened response headers, CORS defaults, request sizes, error handling, CSV exports, and shutdown behavior.
- Updated the production image to include Nmap, the NSE script, a non-root runtime, and a health check.

### Fixed

- Nmap scans no longer depend on ICMP ping or an HTTP response.
- Nmap output parsing now handles standard pipe prefixes, urgent warnings, and negative expired-day values.
- Batch failures are counted correctly.
- Empty optional notification fields no longer fail schedule validation.
- Scheduled-scan updates can no longer overwrite arbitrary record fields.
