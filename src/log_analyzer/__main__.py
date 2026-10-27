from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from log_analyzer.core import Report, analyze_lines
from log_analyzer.io import (
    load_ip_list,
    print_console_report,
    read_lines,
    render_html_report,
    resolve_output_paths,
    write_csv_report,
    write_json_report,
)
from log_analyzer.parsers import BaseParser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Security log analyzer -- parses SSH, Nginx, and Apache logs, "
        "detects brute-force activity, and generates structured reports.",
        epilog="""examples:
  log-analyzer --file /var/log/auth.log
  log-analyzer --file access.log --log-format access --fail-threshold 5
  log-analyzer --file auth.log --watch --rate-limit 10 --rate-window 60
  log-analyzer --file auth.log --siem-out events.jsonl
  log-analyzer --file auth.log --allowlist trusted_ips.txt --blocklist known_bad.txt
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--file", "-f", type=Path, required=True, help="Path to the log file to analyze")
    p.add_argument(
        "--log-format",
        choices=["auto", "ssh", "access", "nginx", "apache"],
        default="auto",
        help="Log format (default: auto-detect). nginx and apache are aliases for access: "
        "both write the same combined log format",
    )
    p.add_argument("--top", "-t", type=int, default=5, help="How many top IPs to show")
    p.add_argument(
        "--fail-threshold",
        type=int,
        default=3,
        help="Alert when an IP's failed count reaches this value",
    )
    p.add_argument(
        "--min-events",
        type=int,
        default=1,
        help="Ignore IPs with fewer than this many total events",
    )
    p.add_argument(
        "--geoip-db",
        type=Path,
        default=None,
        help="Path to GeoLite2-Country.mmdb for country lookup",
    )

    output = p.add_argument_group("output")
    output.add_argument("--format", choices=["csv", "json", "html", "all"], default="all")
    output.add_argument(
        "--out", "-o", type=Path, default=Path("reports"), help="Report output file or directory"
    )
    output.add_argument(
        "--siem-out",
        type=Path,
        default=None,
        help="Write SIEM-format JSONL events to this path (one event per line)",
    )

    db = p.add_argument_group("database")
    db.add_argument("--no-db", action="store_true", help="Skip saving to database")
    db.add_argument("--db", type=Path, default=Path("reports.db"))
    db.add_argument("--db-type", choices=["sqlite", "mysql"], default="sqlite")
    db.add_argument("--db-host", default="localhost")
    db.add_argument("--db-user", default="root")
    db.add_argument("--db-password", default="")
    db.add_argument("--db-name", default="log_analyzer")

    watch = p.add_argument_group("watch mode")
    watch.add_argument(
        "--watch", action="store_true", help="Tail the log file and print alerts in real time"
    )
    watch.add_argument("--rate-window", type=int, default=60, help="Rate alert window in seconds")
    watch.add_argument(
        "--rate-limit",
        type=int,
        default=10,
        help="Max events per IP per window before an alert fires",
    )

    filtering = p.add_argument_group("filtering")
    filtering.add_argument(
        "--allowlist", type=Path, default=None, help="File of IPs to skip entirely, one per line"
    )
    filtering.add_argument(
        "--blocklist",
        type=Path,
        default=None,
        help="File of known-bad IPs, one per line. They are always reported, and a "
        "successful login from one makes the run CRITICAL",
    )

    return p.parse_args(argv)


def _select_parser(args: argparse.Namespace, lines: list[str]) -> BaseParser:
    """Pick the log parser: explicit --log-format, or auto-detect from the file."""
    from log_analyzer.parsers import PARSERS, detect_parser

    if args.log_format == "auto":
        parser = detect_parser(lines)
        print(f"Log format: {parser.name} (auto-detected)")
    else:
        parser = PARSERS[args.log_format]()
        print(f"Log format: {parser.name}")
    return parser


def _write_reports(
    args: argparse.Namespace,
    report: Report,
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
) -> None:
    """Write CSV / JSON / HTML report files according to --format."""
    json_out, csv_out, html_out = resolve_output_paths(args.out, args.file.stem)
    fmt = args.format

    if fmt in ("all", "csv"):
        write_csv_report(
            csv_out,
            ip_counter,
            failed_counter,
            accepted_counter,
            args.fail_threshold,
            blocklisted={ip for ip, _ in report.blocklisted},
        )
        print(f"Wrote CSV  -> {csv_out}")

    if fmt in ("all", "json"):
        write_json_report(json_out, report)
        print(f"Wrote JSON -> {json_out}")

    if fmt in ("all", "html"):
        html_doc = render_html_report(
            args.file.name,
            report,
            ip_counter,
            failed_counter,
            accepted_counter,
            args.fail_threshold,
        )
        html_out.write_text(html_doc, encoding="utf-8")
        print(f"Wrote HTML -> {html_out}")


def _write_siem_events(args: argparse.Namespace, lines: list[str], parser: BaseParser) -> None:
    """Write SIEM-format JSONL events, only if --siem-out was given."""
    if not args.siem_out:
        return
    from log_analyzer.siem import build_siem_events, write_siem_jsonl

    events = build_siem_events(lines, parser, str(args.file), args.fail_threshold)
    write_siem_jsonl(args.siem_out, events)
    print(f"Wrote {len(events)} SIEM events -> {args.siem_out}")


def _persist_to_storage(args: argparse.Namespace, report: Report) -> None:
    """Save the report to SQLite or MySQL, unless --no-db was given."""
    if args.no_db:
        return
    from log_analyzer.storage import MySQLStore, SQLiteStore

    if args.db_type == "mysql":
        store = MySQLStore(args.db_host, args.db_user, args.db_password, args.db_name)
    else:
        store = SQLiteStore(args.db)

    run_id = store.save(report)
    print(f"Saved to {args.db_type} DB (run #{run_id})")


def _run_watch_mode(args: argparse.Namespace, parser: BaseParser) -> None:
    """Tail the log file and print real-time rate-limit alerts. Never returns."""
    if not args.watch:
        return
    from log_analyzer.core import RateTracker
    from log_analyzer.watch import tail_file

    tracker = RateTracker(window_seconds=args.rate_window, max_events=args.rate_limit)

    def on_line(line: str) -> None:
        event = parser.parse_line(line)
        if event and event.event_type == "failed":
            if tracker.record(event.ip):
                print(
                    f"[RATE ALERT] {event.ip} -- exceeded "
                    f"{args.rate_limit} events in {args.rate_window}s"
                )

    tail_file(args.file, on_line)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        lines = read_lines(args.file)
        allowlist = load_ip_list(args.allowlist)
        blocklist = load_ip_list(args.blocklist)
    except OSError as e:
        print(f"error: cannot read {e.filename or args.file}: {e.strerror or e}", file=sys.stderr)
        return 2

    parser = _select_parser(args, lines)

    report, ip_counter, failed_counter, accepted_counter = analyze_lines(
        lines,
        top=args.top,
        fail_threshold=args.fail_threshold,
        min_events=args.min_events,
        file=str(args.file),
        allowlist=allowlist,
        blocklist=blocklist,
        parser=parser,
    )

    print_console_report(report, args.top, args.fail_threshold, geoip_db=args.geoip_db)
    _write_reports(args, report, ip_counter, failed_counter, accepted_counter)
    _write_siem_events(args, lines, parser)
    _persist_to_storage(args, report)  # must run before watch -- tail_file() never returns
    _run_watch_mode(args, parser)

    return 0


if __name__ == "__main__":
    sys.exit(main())
