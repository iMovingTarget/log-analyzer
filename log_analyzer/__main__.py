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
from log_analyzer.storage import SQLiteStore  # Ensure this is imported for your SQLite persistence task


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
    
    # Optional: If you still want the --log-format option, add it cleanly right here:
    p.add_argument(
        "--log-format", 
        choices=["auto", "ssh", "nginx", "apache"], 
        default="auto", 
        help="Format of the log file (default: auto)"
    )
    return p.parse_args()


def main() -> int:
    # 1. Use the clean parsing function from above
    args = parse_args()

    # 2. File read attempt (with proper path resolution because type=Path is in parse_args)
    try:
        lines = read_lines(args.file)
    except FileNotFoundError:
        print(f"File not found: {args.file}")
        return 2

    # --- Your ongoing analysis logic below (e.g., SQLite tracking) ---
    # Example snippet for your implementation task:
    # store = SQLiteStore(Path("reports.db"))
    # run_num = store.save_report(...)
    # print(f"Saved to DB: reports.db (run #{run_num})")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())