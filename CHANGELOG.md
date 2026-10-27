# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-10-27

### Fixed
- A single non-UTF-8 byte in a log no longer crashes the run; undecodable bytes are replaced.
- Successful logins from blocklisted IPs were counted as failures. They are now kept as
  successes, always reported, and make the run CRITICAL.
- Log format detection no longer flips a web log to the SSH parser when "sshd" appears anywhere
  in it; every parser is scored on a sample and the best match wins.
- SIEM events carry the time the event happened (from the log line) instead of the ingest time
  shared by every event.
- SIEM event severity was always INFO. It now escalates per IP as failures accumulate, and a
  successful login after a brute-force run is CRITICAL.
- `--watch` kept reading at a stale offset after log rotation and went silent. It now follows
  rotation and truncation and never splits a partially written line.
- The rate tracker used by `--watch` never evicted idle IPs, so memory grew without bound.
- Chart labels for IPv6 addresses were clipped in the HTML report.
- Invalid table markup in the HTML report; console output is now plain ASCII, which avoids a
  crash on Windows when output is redirected.
- SQLite connections are closed after use instead of keeping the database file locked.

### Changed
- nginx and Apache share one `access` parser (they write the same format); `--log-format nginx`
  and `--log-format apache` remain as aliases.
- A missing `--allowlist`, `--blocklist` or `--geoip-db` file is an error instead of being
  ignored.
- `--db-password` defaults to `$LOG_ANALYZER_DB_PASSWORD` so the password stays out of the
  process list and shell history.
- SIEM events gain `ingested_at` and `reason` fields.
- Redesigned HTML report.
- Source moved to a `src/` layout; packaging metadata completed; `dev` extra added.
- CI tests Python 3.10 to 3.14 on Linux and 3.14 on Windows, and runs Ruff.

### Added
- `--version`.
- `Accepted publickey` and `keyboard-interactive` logins are recognised.
- RFC 3339 syslog timestamps (rsyslog high-precision, `journalctl -o short-iso`).
- Example logs in `examples/`.

## Earlier versions

0.1 to 0.4 were developed before this changelog existed; see the git history.

[0.5.0]: https://github.com/iMovingTarget/log_analyzer/releases/tag/v0.5.0
