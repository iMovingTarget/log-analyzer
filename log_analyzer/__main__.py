from __future__ import annotations


import argparse
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Mini Log Analyzer: stats + alerts + JSON report",
    )
    p.add_argument(
        "--format",
        choices=["csv", "json", "html", "all"],
        default="all",
        help="Which report to generate (default: all)",
    )
    p.add_argument(
    "--min-events",
    type=int,
    default=1,
    help="Ignore IPs with total events < this value (default: 1)",
    )
    p.add_argument("--file", "-f", type=Path, required=True, help="Path to log file")
    p.add_argument("--top", "-t", type=int, default=5, help="How many top IPs to show")
    p.add_argument("--fail-threshold", type=int, default=3, help="Alert if failed count >= this")
    p.add_argument("--out", "-o", type=Path, default=Path("reports"), help="Report output file or directory")
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
    file=str(args.file),   # <-- add this
    )


    print_console_report(report, args.top, args.fail_threshold)
    json_out, csv_out, html_out = resolve_output_paths(args.out, args.file.stem)

    fmt = args.format
    if fmt in ("all", "csv"):
        write_csv_report(csv_out, ip_counter, failed_counter, accepted_counter, args.fail_threshold)
        print(f"Wrote CSV report to: {csv_out}")

    if fmt in ("all", "json"):
        write_json_report(json_out, report)
        print(f"Wrote JSON report to: {json_out}")

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
        print(f"Wrote HTML report to: {html_out}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
