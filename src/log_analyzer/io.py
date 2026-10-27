from __future__ import annotations

import csv
import html
import json
from collections import Counter
from collections.abc import Collection
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from log_analyzer.core import Report, Severity

HTML_STYLE = """
body { font-family: system-ui, Arial, sans-serif; margin: 24px; }
.meta { margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #f5f5f5; }
tr.alert { background: #fff3cd; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eee; }
.badge.alert { background: #ffecb5; }
.controls {
  display: flex; gap: 12px; align-items: center; margin: 12px 0 16px; flex-wrap: wrap;
}
.controls input[type="search"] {
  padding: 8px 10px; border: 1px solid #ddd; border-radius: 8px; min-width: 260px;
}
.controls label { display: inline-flex; gap: 8px; align-items: center; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { text-decoration: underline; }
.small { color: #666; font-size: 0.9em; }
.sev { font-weight: 700; }
.sev-warning { color: #8a5a00; }
.sev-critical { color: #b02a37; }
.banner {
  margin-top: 12px; padding: 10px 12px; border-radius: 8px;
  background: #f8d7da; color: #58151c; font-weight: 600;
}
""".strip()


@dataclass(frozen=True)
class Row:
    ip: str
    total: int
    failed: int
    accepted: int
    alert: bool
    blocklisted: bool = False


def _esc(x: object) -> str:
    return html.escape(str(x))


def _td(x: object) -> str:
    return f"<td>{_esc(x)}</td>"


def read_lines(path: Path) -> list[str]:
    """Read a log file as a list of lines.

    Undecodable bytes become U+FFFD instead of raising: real auth logs contain
    binary junk (scanners send raw bytes as usernames), and one bad byte must
    not abort the whole analysis.
    """
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def resolve_output_paths(out: Path, file_stem: str) -> tuple[Path, Path, Path]:
    if out.suffix == "":
        out.mkdir(parents=True, exist_ok=True)
        return (
            out / f"{file_stem}.json",
            out / f"{file_stem}.csv",
            out / f"{file_stem}.html",
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    return (
        out.with_suffix(".json"),
        out.with_suffix(".csv"),
        out.with_suffix(".html"),
    )


def print_console_report(
    report: Report, top: int, fail_threshold: int, geoip_db: Path | None = None
) -> None:
    """Print a plain-ASCII summary (safe on any console encoding, and when redirected)."""
    shown = [ip for ip, _ in (*report.top_ips, *report.failed_by_ip, *report.blocklisted)]
    width = max([15, *map(len, shown)])

    def row(ip: str, detail: str) -> str:
        country = f"  [{lookup_country(ip, geoip_db) or '??'}]" if geoip_db else ""
        return f"  {ip:<{width}}  {detail}{country}"

    name = Path(report.file).name if report.file else "(stdin)"
    lines = [
        f"\nlog-analyzer report: {name}",
        f"Severity: {Severity(report.severity).value}",
        f"Lines: {report.total_lines} | Accepted: {report.accepted_total}"
        f" | Failed: {report.failed_total}",
        "",
        f"Top {top} IPs by events:",
        *(row(ip, f"{n:>6}") for ip, n in report.top_ips),
        "",
        f"Top {top} IPs by failures:",
        *(row(ip, f"{n:>6}") for ip, n in report.failed_by_ip),
        "",
    ]
    if report.alerts:
        lines += [
            f"ALERTS (failed >= {fail_threshold}):",
            *(row(ip, f"failed={n}") for ip, n in report.alerts),
        ]
    else:
        lines += [f"No IP reached the failure threshold ({fail_threshold})."]

    if report.blocklisted:
        lines += [
            "",
            "BLOCKLISTED IPs seen:",
            *(row(ip, f"events={n}") for ip, n in report.blocklisted),
        ]
    lines += [f"!! Successful login from blocklisted IP {ip}" for ip in report.blocklisted_logins]

    print("\n".join(lines))


def write_csv_report(
    csv_out: Path,
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
    fail_threshold: int,
    blocklisted: Collection[str] = (),
) -> None:
    with csv_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "total", "failed", "accepted", "alert", "blocklisted"])
        for r in _build_rows(
            ip_counter, failed_counter, accepted_counter, fail_threshold, blocklisted
        ):
            w.writerow(
                [
                    r.ip,
                    r.total,
                    r.failed,
                    r.accepted,
                    "YES" if r.alert else "",
                    "YES" if r.blocklisted else "",
                ]
            )


def write_json_report(json_out: Path, report: Report) -> None:
    json_out.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def _build_rows(
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
    fail_threshold: int,
    blocklisted: Collection[str] = (),
) -> list[Row]:
    rows: list[Row] = []
    for ip, total in ip_counter.most_common():
        failed = failed_counter.get(ip, 0)
        rows.append(
            Row(
                ip=ip,
                total=total,
                failed=failed,
                accepted=accepted_counter.get(ip, 0),
                alert=failed >= fail_threshold or ip in blocklisted,
                blocklisted=ip in blocklisted,
            )
        )
    return rows


def _render_blocklist_banner(report: Report) -> str:
    if not report.blocklisted_logins:
        return ""
    ips = ", ".join(_esc(ip) for ip in report.blocklisted_logins)
    return f'\n    <div class="banner">Successful login from blocklisted IP: {ips}</div>'


def _render_meta(file_name: str, report: Report, fail_threshold: int) -> str:
    severity = Severity(report.severity).value
    badge_class = "badge alert" if report.alerts else "badge"
    badge_text = "ALERTS present" if report.alerts else "No alerts"

    return f"""
  <div class="meta">
    <div><b>File:</b> {_esc(file_name)}</div>
    <div><b>Severity:</b> <span class="sev sev-{severity.lower()}">{severity}</span></div>
    <div><b>Total lines:</b> {report.total_lines}</div>
    <div><b>Accepted:</b> {report.accepted_total} &nbsp; <b>Failed:</b> {report.failed_total}</div>
    <div><b>Fail threshold:</b> {fail_threshold}</div>
    <div class="{badge_class}">{badge_text}</div>{_render_blocklist_banner(report)}
  </div>
""".strip()


def _render_table(rows: list[Row]) -> str:
    header = """
  <table>
    <thead>
      <tr>
        <th class="sortable" data-key="ip" data-type="text">IP</th>
        <th class="sortable" data-key="total" data-type="num">Total</th>
        <th class="sortable" data-key="failed" data-type="num">Failed</th>
        <th class="sortable" data-key="accepted" data-type="num">Accepted</th>
        <th class="sortable" data-key="alert" data-type="text">Alert</th>
      </tr>
    </thead>
    <tbody>
""".rstrip()

    body_lines: list[str] = []
    for r in rows:
        alert_text = "BLOCKLISTED" if r.blocklisted else ("YES" if r.alert else "")
        cells = f"{_td(r.ip)}{_td(r.total)}{_td(r.failed)}{_td(r.accepted)}{_td(alert_text)}"
        cls = "alert" if r.alert else ""
        body_lines.append(
            f"<tr class='{cls}' data-ip='{_esc(r.ip)}' data-total='{r.total}' "
            f"data-failed='{r.failed}' data-accepted='{r.accepted}' data-alert='{alert_text}'>"
            f"{cells}</tr>"
        )
    footer = """
    </tbody>
  </table>
""".strip()

    return "\n".join([header, *body_lines, footer])


def render_html_report(
    file_name: str,
    report: Report,
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
    fail_threshold: int,
) -> str:
    blocklisted = {ip for ip, _ in report.blocklisted}
    rows = _build_rows(ip_counter, failed_counter, accepted_counter, fail_threshold, blocklisted)
    meta_html = _render_meta(file_name, report, fail_threshold)
    chart_html = _render_bar_chart(rows)
    table_html = _render_table(rows)

    controls_html = """
  <div class="controls">
    <input id="q" type="search" placeholder="Search IP / numbers…" autocomplete="off" />
    <label><input id="onlyAlerts" type="checkbox" /> Only alerts</label>
    <span class="small" id="count"></span>
  </div>
""".strip()

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Log Report - {_esc(file_name)}</title>
  <style>
    {HTML_STYLE}
  </style>
</head>
<body>
  <h1>Log report</h1>
  {meta_html}

  {chart_html}

  {controls_html}

  <h2>By IP</h2>
  {table_html}

  <script>
    (function () {{
      const q = document.getElementById('q');
      const onlyAlerts = document.getElementById('onlyAlerts');
      const count = document.getElementById('count');
      const tbody = document.querySelector('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const headers = Array.from(document.querySelectorAll('th.sortable'));

      function visibleRows() {{
        const query = (q.value || '').trim().toLowerCase();
        const only = !!onlyAlerts.checked;
        let shown = 0;

        for (const tr of rows) {{
          const hay = [
            tr.dataset.ip,
            tr.dataset.total,
            tr.dataset.failed,
            tr.dataset.accepted,
            tr.dataset.alert
          ].join(' ').toLowerCase();

          const matchQuery = !query || hay.includes(query);
          const matchAlert = !only || tr.classList.contains('alert');

          const show = matchQuery && matchAlert;
          tr.style.display = show ? '' : 'none';
          if (show) shown++;
        }}
        count.textContent = `Showing ${{shown}} / ${{rows.length}}`;
      }}

      function sortBy(key, type, direction) {{
        const dir = direction === 'desc' ? -1 : 1;
        const get = (tr) => tr.dataset[key] ?? '';

        const compare = (a, b) => {{
          const va = get(a);
          const vb = get(b);
          if (type === 'num') {{
            return (Number(va) - Number(vb)) * dir;
          }}
          return va.localeCompare(vb) * dir;
        }};

        const sorted = rows.slice().sort(compare);
        for (const tr of sorted) tbody.appendChild(tr);
      }}

      q.addEventListener('input', visibleRows);
      onlyAlerts.addEventListener('change', visibleRows);

      const state = {{ key: null, dir: 'asc' }};
      headers.forEach((th) => {{
        th.addEventListener('click', () => {{
          const key = th.dataset.key;
          const type = th.dataset.type || 'text';
          state.dir = (state.key === key && state.dir === 'asc') ? 'desc' : 'asc';
          state.key = key;
          sortBy(key, type, state.dir);
          visibleRows();
        }});
      }});

      visibleRows();
    }})();
  </script>
</body>
</html>
"""


def load_ip_list(path: Path | None) -> set[str]:
    """Load IPs from a file, one per line. Blank lines and # comments are ignored.

    A path that was given but does not exist raises FileNotFoundError. Treating a
    mistyped allowlist as empty would silently switch filtering off.
    """
    if path is None:
        return set()
    entries: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            entries.add(entry)
    return entries


_geoip_reader_cache: dict[str, Any] = {}


def lookup_country(ip: str, db_path: Path | None) -> str | None:
    if db_path is None or not db_path.exists():
        return None
    key = str(db_path)
    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        return None
    try:
        if key not in _geoip_reader_cache:
            _geoip_reader_cache[key] = geoip2.database.Reader(key)
        return _geoip_reader_cache[key].country(ip).country.iso_code
    except (geoip2.errors.AddressNotFoundError, ValueError, OSError):
        return None


def _render_bar_chart(rows: list[Row], max_bars: int = 10) -> str:
    top = sorted(rows, key=lambda r: r.failed, reverse=True)[:max_bars]
    top = [r for r in top if r.failed > 0]
    if not top:
        return ""

    max_failed = max(r.failed for r in top) or 1
    bar_height = 22
    gap = 6
    chart_height = len(top) * (bar_height + gap)
    label_width = 140
    chart_width = 420
    svg_width = label_width + chart_width + 50

    bars = []
    for i, r in enumerate(top):
        y = i * (bar_height + gap)
        w = int((r.failed / max_failed) * chart_width)
        color = "#d9534f" if r.alert else "#5b8def"
        bars.append(
            f'<text x="{label_width - 8}" y="{y + 15}" text-anchor="end" '
            f'font-size="12">{_esc(r.ip)}</text>'
            f'<rect x="{label_width}" y="{y}" width="{w}" height="{bar_height}" '
            f'fill="{color}" rx="3"></rect>'
            f'<text x="{label_width + w + 6}" y="{y + 15}" '
            f'font-size="12">{r.failed}</text>'
        )

    return (
        "<h2>Top failed IPs</h2>\n"
        f'<svg width="{svg_width}" height="{chart_height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img">\n' + "\n".join(bars) + "\n</svg>"
    )
