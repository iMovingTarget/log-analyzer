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
    p.add_argument("--db-type", choices=["sqlite","mysql"], default="sqlite")
    p.add_argument("--db-host", default="localhost")
    p.add_argument("--db-user", default="root")
    p.add_argument("--db-password", default="")
    p.add_argument("--db-name", default="log_analyzer")
    p.add_argument(
        "--watch",
        action="store_true",
        help="Tail the log file and print alerts in real time",
    )
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


    if args.watch:
        from log_analyzer.parsers import detect_parser
        from log_analyzer.watch import tail_file

        lines_sample = lines[:200]
        parser = detect_parser(lines_sample)
        print(f"[watch] Parser: {type(parser).__name__}")
        threshold = args.fail_threshold

        counts: dict[str, int] = {}

        def on_line(line: str) -> None:
            event = parser.parse_line(line)
            if event and event.event_type == "failed":
                counts[event.ip] = counts.get(event.ip, 0) + 1
                if counts[event.ip] >= threshold:
                    print(f"[ALERT] {event.ip} — {counts[event.ip]} failures")

        tail_file(args.file, on_line)


    if not args.no_db:
        from log_analyzer.storage import SQLiteStore, MySQLStore
        if args.db_type == "mysql":
            store = MySQLStore(args.db_host, args.db_user,
                            args.db_password, args.db_name)
        else:
            store = SQLiteStore(args.db)
        run_id = store.save(report)
        print(f"Saved to {args.db_type} DB (run #{run_id})")

    return 0


if __name__ == "__main__":
    sys.exit(main())