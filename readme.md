# CLI Log Analyzer (Python)

A small CLI tool that parses SSH/auth-style logs (and a sample format), aggregates events by IP, detects brute-force-like activity, and generates reports.

## Features
- Parse log file from CLI (`--file`)
- Extract IPv4 using regex
- Classify events:
  - **failed**: `failed password`, `invalid user`
  - **accepted**: `accepted password`
- Aggregation:
  - total events per IP
  - failed per IP
  - accepted per IP
- Alerts when `failed >= --fail-threshold`
- Reports:
  - JSON
  - CSV
  - HTML
- Select output format via `--format` (`csv|json|html|all`)

## Project structure
- `log_analyzer/core.py` — pure logic (parsing + aggregation), easy to test
- `log_analyzer/io.py` — reading files + writing CSV/JSON + HTML rendering
- `log_analyzer/__main__.py` — CLI entrypoint (orchestrates the flow)
- `tests/` — pytest unit tests for core

## Requirements
- Python 3.10+ (recommended)
- Windows / macOS / Linux

## Run
From the project root:

```powershell
python -m log_analyzer --file auth_sample.log --fail-threshold 3