from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path
from dataclasses import asdict, dataclass
from log_analyzer.core import Report


HTML_STYLE = """
body { font-family: system-ui, Arial, sans-serif; margin: 24px; }
.meta { margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background: #f5f5f5; }
tr.alert { background: #fff3cd; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eee; }
.badge.alert { background: #ffecb5; }
.controls { display: flex; gap: 12px; align-items: center; margin: 12px 0 16px; flex-wrap: wrap; }
.controls input[type="search"] { padding: 8px 10px; border: 1px solid #ddd; border-radius: 8px; min-width: 260px; }
.controls label { display: inline-flex; gap: 8px; align-items: center; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { text-decoration: underline; }
.small { color: #666; font-size: 0.9em; }
""".strip()


@dataclass(frozen=True)
class Row:
    ip: str
    total: int
    failed: int
    accepted: int
    alert: bool


def _esc(x: object) -> str:
    return html.escape(str(x))


def _td(x: object) -> str:
    return f"<td>{_esc(x)}</td>"


def _tr(cells: str, *, alert: bool) -> str:
    cls = "alert" if alert else ""
    return f"<tr class='{cls}'>{cells}</tr>"


def read_lines(path: Path) -> list[str]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8").splitlines()


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

def print_console_report(report: Report, top: int, fail_threshold: int, geoip_db: Path | None = None) -> None:
    file_name = Path(report.file).name if report.file else ""

    top_ips_formatted = [
        f"  {ip:15}  {n:5}  [{lookup_country(ip, geoip_db) or '??'}]"
        for ip, n in report.top_ips
    ]
    
    failed_by_ip_formatted = [
        f"  {ip:15}  {n:5}  [{lookup_country(ip, geoip_db) or '??'}]"
        for ip, n in report.failed_by_ip
    ]

    lines: list[str] = [
        f"\nFile: {file_name}",
        f"Total lines: {report.total_lines}",
        f"Accepted: {report.accepted_total} | Failed: {report.failed_total}",
        "",
        f"Top {top} IPs:",
        *top_ips_formatted,
        "",
        f"Top {top} FAILED by IP:",
        *failed_by_ip_formatted,
    ]

    if report.alerts:
        lines += [
            "",
            "ALERTS (failed >= threshold):",
            *[
                f"  {ip:15}  failed={n:<5} (threshold={fail_threshold})  [{lookup_country(ip, geoip_db) or '??'}]"
                for ip, n in report.alerts
            ],
        ]
    else:
        lines += ["", "No alerts 🎉"]

    print(f"Severity: {getattr(report.severity, 'value', report.severity)}")
    print("\n".join(lines))


def write_csv_report(
    csv_out: Path,
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
    fail_threshold: int,
) -> None:
    with csv_out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "total", "failed", "accepted", "alert"])

        for ip, total in ip_counter.most_common():
            failed = failed_counter.get(ip, 0)
            accepted = accepted_counter.get(ip, 0)
            alert = "YES" if failed >= fail_threshold else ""
            w.writerow([ip, total, failed, accepted, alert])


def write_json_report(json_out: Path, report: Report) -> None:
    json_out.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def _build_rows(
    ip_counter: Counter[str],
    failed_counter: Counter[str],
    accepted_counter: Counter[str],
    fail_threshold: int,
) -> list[Row]:
    rows: list[Row] = []
    for ip, total in ip_counter.most_common():
        failed = failed_counter.get(ip, 0)
        accepted = accepted_counter.get(ip, 0)
        rows.append(Row(ip=ip, total=total, failed=failed, accepted=accepted, alert=failed >= fail_threshold))
    return rows


def _render_meta(file_name: str, report: Report, fail_threshold: int) -> str:
    badge_class = "badge alert" if report.alerts else "badge"
    badge_text = "ALERTS present" if report.alerts else "No alerts"

    return f"""
  <div class="meta">
    <div><b>File:</b> {_esc(file_name)}</div>
    <div><b>Total lines:</b> {report.total_lines}</div>
    <div><b>Accepted:</b> {report.accepted_total} &nbsp; <b>Failed:</b> {report.failed_total}</div>
    <div><b>Fail threshold:</b> {fail_threshold}</div>
    <div class="{badge_class}">{badge_text}</div>
  </div>
""".strip()


def _render_table(rows: list[Row]) -> str:
    header = """
  <table>
    <thead>
        <th class="sortable" data-key="ip" data-type="text">IP</th>
        <th class="sortable" data-key="total" data-type="num">Total</th>
        <th class="sortable" data-key="failed" data-type="num">Failed</th>
        <th class="sortable" data-key="accepted" data-type="num">Accepted</th>
        <th class="sortable" data-key="alert" data-type="text">Alert</th>
    </thead>
    <tbody>
""".rstrip()

    body_lines: list[str] = []
    for r in rows:
        alert_text = "YES" if r.alert else ""
        cells = f"{_td(r.ip)}{_td(r.total)}{_td(r.failed)}{_td(r.accepted)}{_td(alert_text)}"
        cls = "alert" if r.alert else ""
        body_lines.append(
            f"<tr class='{cls}' data-ip='{_esc(r.ip)}' data-total='{r.total}' data-failed='{r.failed}' "
            f"data-accepted='{r.accepted}' data-alert='{alert_text}'>"
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
    rows = _build_rows(ip_counter, failed_counter, accepted_counter, fail_threshold)
    meta_html = _render_meta(file_name, report, fail_threshold)
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
    if path is None or not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


_geoip_reader_cache: dict[str, "geoip2.database.Reader"] = {}

def lookup_country(ip: str, db_path: Path | None) -> str | None:
    if db_path is None or not db_path.exists():
        return None
    key = str(db_path)
    try:
        import geoip2.database
        if key not in _geoip_reader_cache:
            _geoip_reader_cache[key] = geoip2.database.Reader(key)
        return _geoip_reader_cache[key].country(ip).country.iso_code
    except Exception:
        return None