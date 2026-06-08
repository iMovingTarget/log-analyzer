from __future__ import annotations

import argparse
import sys
from pathlib import Path

from log_analyzer.core import analyze_lines
from log_analyzer.io import (
    read_lines,
    resolve_output_paths,
    print_console_report,
    write_csv_report,
    write_json_report,
    render_html_report,
)
from log_analyzer.storage import SQLiteStore


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Mini Log Analyzer: stats + alerts + JSON report",
    )
    p.add_argument("--format", choices=["csv", "json", "html", "all"], default="all")
    p.add_argument("--min-events", type=int, default=1)
    p.add_argument("--file", "-f", type=Path, required=True)
    p.add_argument("--top", "-t", type=int, default=5)
    p.add_argument("--fail-threshold", type=int, default=3)
    p.add_argument("--out", "-o", type=Path, default=Path("reports"))
    p.add_argument("--log-format", choices=["auto", "ssh", "nginx", "apache"], default="auto")
    p.add_argument("--no-db", action="store_true", help="Skip saving to database")
    p.add_argument("--db", type=Path, default=Path("reports.db"))
    return p.parse_args()


def main() -> int:
    args = parse_args()

    try:
        lines = read_lines(args.file)
    except FileNotFoundError:
        print(f"File not found: {args.file}")
        return 2

    report, ip_counter, failed_counter, accepted_counter = analyze_lines(
        lines,
        top=args.top,
        fail_threshold=args.fail_threshold,
        min_events=args.min_events,
        file=str(args.file),
    )

    print_console_report(report, args.top, args.fail_threshold)

    json_out, csv_out, html_out = resolve_output_paths(args.out, args.file.stem)

    fmt = args.format
    if fmt in ("all", "csv"):
        write_csv_report(csv_out, ip_counter, failed_counter, accepted_counter, args.fail_threshold)
        print(f"Wrote CSV  → {csv_out}")

    if fmt in ("all", "json"):
        write_json_report(json_out, report)
        print(f"Wrote JSON → {json_out}")

    if fmt in ("all", "html"):
        html_doc = render_html_report(
            args.file.name, report,
            ip_counter, failed_counter, accepted_counter,
            args.fail_threshold,
        )
        html_out.write_text(html_doc, encoding="utf-8")
        print(f"Wrote HTML → {html_out}")

    if not args.no_db:
        store = SQLiteStore(args.db)
        run_id = store.save(report)
        print(f"Saved to DB: {args.db} (run #{run_id})")

    return 0


if __name__ == "__main__":
    sys.exit(main())