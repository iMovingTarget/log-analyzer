from __future__ import annotations

import csv
import html
import json
from collections import Counter
from collections.abc import Collection
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from log_analyzer import __version__
from log_analyzer.core import Report, Severity

HTML_STYLE = """
:root {
  --bg: #f6f7f9; --card: #fff; --text: #1f2328; --muted: #656d76; --border: #e4e7eb;
  --red: #b4233a; --red-bg: #fdecef; --red-line: #f3c3cb;
  --amber: #8a5a00; --amber-bg: #fff4d6; --amber-line: #f2dca0;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 1040px; margin: 0 auto; padding: 32px 20px 40px; }
header {
  display: flex; align-items: flex-end; justify-content: space-between;
  gap: 16px; flex-wrap: wrap; margin-bottom: 20px;
}
.eyebrow { color: var(--muted); font-size: 13px; }
h1 { margin: 2px 0 0; font-size: 26px; line-height: 1.2; word-break: break-all; }
h2 { margin: 0 0 14px; font-size: 16px; }
.sev {
  display: inline-block; padding: 5px 14px; border-radius: 999px;
  font-weight: 700; font-size: 13px; border: 1px solid var(--border);
}
.sev-info { background: #eef1f4; color: var(--muted); }
.sev-warning {
  background: var(--amber-bg); color: var(--amber); border-color: var(--amber-line);
}
.sev-critical {
  background: var(--red-bg); color: var(--red); border-color: var(--red-line);
}
.stats {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px;
}
.stat {
  background: var(--card); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 14px;
}
.stat .label {
  color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
}
.stat .value { font-size: 24px; font-weight: 650; font-variant-numeric: tabular-nums; }
.banner { margin-top: 16px; padding: 12px 16px; border-radius: 10px; font-weight: 600; }
.banner-critical {
  background: var(--red-bg); color: var(--red); border: 1px solid var(--red-line);
}
.banner-warning {
  background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-line);
}
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 18px 20px; margin-top: 16px;
}
.chart svg { display: block; max-width: 100%; height: auto; }
.controls { display: flex; gap: 16px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.controls input[type="search"] {
  padding: 8px 12px; border: 1px solid var(--border); border-radius: 8px;
  min-width: 260px; font: inherit;
}
.controls label { display: inline-flex; gap: 8px; align-items: center; }
.muted { color: var(--muted); font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th, td { padding: 9px 10px; border-bottom: 1px solid var(--border); text-align: left; }
td { vertical-align: baseline; }
th {
  font-size: 12px; font-weight: 600; color: var(--muted);
  text-transform: uppercase; letter-spacing: .04em;
}
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text); }
th.num, td.num { text-align: right; }
td.ip { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 14px; }
tr.alert td { background: #fffbf2; }
tbody tr:last-child td { border-bottom: 0; }
.pill {
  display: inline-block; padding: 1px 9px; border-radius: 999px;
  font-size: 12px; font-weight: 700;
}
.pill-alert { background: var(--amber-bg); color: var(--amber); }
.pill-block { background: var(--red-bg); color: var(--red); }
footer { margin-top: 20px; color: var(--muted); font-size: 12px; }
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


def _render_banners(report: Report) -> str:
    if report.blocklisted_logins:
        ips = ", ".join(_esc(ip) for ip in report.blocklisted_logins)
        return (
            f'<div class="banner banner-critical">Successful login from blocklisted IP: {ips}</div>'
        )
    if report.blocklisted:
        ips = ", ".join(_esc(ip) for ip, _ in report.blocklisted)
        return f'<div class="banner banner-warning">Blocklisted IPs seen: {ips}</div>'
    return ""


def _render_stats(report: Report, unique_ips: int, fail_threshold: int) -> str:
    stats = [
        ("Lines", report.total_lines),
        ("Unique IPs", unique_ips),
        ("Accepted", report.accepted_total),
        ("Failed", report.failed_total),
        ("Alerting IPs", len(report.alerts)),
        ("Fail threshold", fail_threshold),
    ]
    cards = "".join(
        f'<div class="stat"><div class="label">{label}</div><div class="value">{value}</div></div>'
        for label, value in stats
    )
    return f'<section class="stats">{cards}</section>'


def _render_table(rows: list[Row]) -> str:
    header = """
  <table>
    <thead>
      <tr>
        <th class="sortable" data-key="ip" data-type="text">IP</th>
        <th class="sortable num" data-key="total" data-type="num">Events</th>
        <th class="sortable num" data-key="failed" data-type="num">Failed</th>
        <th class="sortable num" data-key="accepted" data-type="num">Accepted</th>
        <th class="sortable" data-key="alert" data-type="text">Alert</th>
      </tr>
    </thead>
    <tbody>
""".rstrip()

    body_lines: list[str] = []
    for r in rows:
        if r.blocklisted:
            alert_text, pill = "BLOCKLISTED", '<span class="pill pill-block">BLOCKLISTED</span>'
        elif r.alert:
            alert_text, pill = "YES", '<span class="pill pill-alert">ALERT</span>'
        else:
            alert_text, pill = "", ""
        body_lines.append(
            f"<tr class='{'alert' if r.alert else ''}' data-ip='{_esc(r.ip)}' "
            f"data-total='{r.total}' data-failed='{r.failed}' data-accepted='{r.accepted}' "
            f"data-alert='{alert_text}'>"
            f"<td class='ip'>{_esc(r.ip)}</td><td class='num'>{r.total}</td>"
            f"<td class='num'>{r.failed}</td><td class='num'>{r.accepted}</td><td>{pill}</td></tr>"
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
    """Render a self-contained HTML report: no external CSS, JS, fonts or images."""
    severity = Severity(report.severity).value
    blocklisted = {ip for ip, _ in report.blocklisted}
    rows = _build_rows(ip_counter, failed_counter, accepted_counter, fail_threshold, blocklisted)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    chart_html = _render_bar_chart(rows)
    chart_section = f'<section class="card chart">{chart_html}</section>' if chart_html else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_esc(file_name)} - log-analyzer report</title>
  <style>
{HTML_STYLE}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <div class="eyebrow">log-analyzer security report</div>
      <h1>{_esc(file_name)}</h1>
    </div>
    <span class="sev sev-{severity.lower()}">Severity: {severity}</span>
  </header>

  {_render_stats(report, len(ip_counter), fail_threshold)}
  {_render_banners(report)}

  {chart_section}

  <section class="card">
    <h2>Activity by IP</h2>
    <div class="controls">
      <input id="q" type="search" placeholder="Filter by IP or number" autocomplete="off" />
      <label><input id="onlyAlerts" type="checkbox" /> Only alerts</label>
      <span class="muted" id="count"></span>
    </div>
    {_render_table(rows)}
  </section>

  <footer>Generated {generated} by log-analyzer {__version__}</footer>
</main>

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
        count.textContent = `Showing ${{shown}} of ${{rows.length}}`;
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

    max_failed = max(r.failed for r in top)
    bar_height, gap = 22, 8
    # Labels use a monospace font, so their width is predictable: ~7.3 px per
    # character at 12 px. Sizing the column to the longest IP keeps IPv6
    # addresses from being clipped.
    label_width = 16 + round(7.3 * max(len(r.ip) for r in top))
    chart_width = 480
    svg_width = label_width + chart_width + 40
    svg_height = len(top) * (bar_height + gap) - gap

    bars = []
    for i, r in enumerate(top):
        y = i * (bar_height + gap)
        w = max(2, round(r.failed / max_failed * chart_width))
        color = "#d1495b" if r.alert else "#6b8fbf"
        bars.append(
            f'<text x="{label_width - 10}" y="{y + 15}" text-anchor="end" font-size="12" '
            f'font-family="ui-monospace, SFMono-Regular, Consolas, monospace" fill="#1f2328">'
            f"{_esc(r.ip)}</text>"
            f'<rect x="{label_width}" y="{y}" width="{w}" height="{bar_height}" '
            f'fill="{color}" rx="4"></rect>'
            f'<text x="{label_width + w + 8}" y="{y + 15}" font-size="12" fill="#656d76">'
            f"{r.failed}</text>"
        )

    return (
        "<h2>Failed attempts by IP</h2>\n"
        f'<svg viewBox="0 0 {svg_width} {svg_height}" width="{svg_width}" height="{svg_height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-label="Bar chart of failed attempts per IP">\n' + "\n".join(bars) + "\n</svg>"
    )
