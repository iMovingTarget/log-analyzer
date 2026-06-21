![Tests](https://github.com/iMovingTarget/log_analyzer/actions/workflows/tests.yml/badge.svg)

# log-analyzer

A production-grade Linux security log analysis CLI tool.
Parses SSH/auth, Nginx, and Apache logs — aggregates events by IP,
detects brute-force activity, classifies severity, and generates reports.

## Features
- Multi-format parsing: SSH/auth, Nginx, Apache (auto-detected)
- IPv4 and IPv6 support
- Severity classification: INFO / WARNING / CRITICAL
- Real-time watch mode (--watch) with rate-based alerting
- Allowlist and blocklist support
- Optional GeoIP country lookup (MaxMind GeoLite2)
- Structured output: JSON (SIEM-ready), CSV, HTML report
- Persistent storage: SQLite (default) or MySQL/MariaDB
- SIEM-ready JSONL event stream (--siem-out) — one structured event per line
- HTML report includes an inline bar chart of top failed IPs
- Installable as a CLI command via pip install -e .
- Tested automatically on every push via GitHub Actions

## Project structure

    log_analyzer/
      core.py      — analysis engine, Report dataclass, RateTracker
      parsers.py   — BaseParser ABC, SSHParser, NginxParser, ApacheParser
      io.py        — file I/O, report rendering, GeoIP lookup
      storage.py   — SQLiteStore, MySQLStore
      watch.py     — real-time log tailing
      __main__.py  — CLI entrypoint
    tests/
      test_core.py
      test_parsers.py
      fixtures/

## Quick start

    pip install -e .
    log-analyzer --file /var/log/auth.log
    log-analyzer --file access.log --log-format nginx --fail-threshold 5
    log-analyzer --file auth.log --watch --rate-limit 10 --rate-window 60
    log-analyzer --file auth.log --siem-out events.jsonl

Run `log-analyzer --help` for the full list of options and examples.

## Requirements
- Python 3.10+
- Optional: geoip2 (pip install geoip2) + GeoLite2-Country.mmdb
- Optional: mysql-connector-python for MySQL backend