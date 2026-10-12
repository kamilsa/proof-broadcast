#!/usr/bin/env python3
"""Parse proof-broadcast EVENT logs into a CLI summary and a self-contained HTML page.

Usage:
  python3 scripts/analyze.py [--serve] [--append] [--port N] DIR [DIR ...]

Every run appended with --append is kept in `<DIR>/runs-history.json`;
`<DIR>/summary.html` is rewritten from that history (inline SVG, no deps).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from html import escape
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import median

EVENT_RE = re.compile(r"EVENT kind=(\S+) t_ms=(\d+)(.*)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
KV_RE = re.compile(r"(\w+)=(\S+)")

SERVE_PORT = 4321
HTML_NAME = "summary.html"
HISTORY_NAME = "runs-history.json"


def parse_event_line(line: str) -> dict | None:
    """Parse one `EVENT kind=... t_ms=... k=v ...` line into a dict, or None."""
    match = EVENT_RE.search(_ANSI.sub("", line).strip())
    if not match:
        return None
    event: dict = {"kind": match.group(1), "t_ms": int(match.group(2))}
    for key, raw in KV_RE.findall(match.group(3)):
        if raw in ("true", "false"):
            event[key] = raw == "true"
        elif raw == "NA":
            event[key] = None
        else:
            try:
                event[key] = int(raw)
            except ValueError:
                try:
                    event[key] = float(raw)
                except ValueError:
                    event[key] = raw
    return event


def iter_host_logs(run_dir: Path) -> list[tuple[str, Path]]:
    hosts = run_dir / "shadow.data" / "hosts"
    if not hosts.is_dir():
        return []
    out = []
    for host in sorted(hosts.iterdir()):
        matches = sorted(host.glob("proof-broadcast.*.stdout")) if host.is_dir() else []
        if matches:
            out.append((host.name, matches[0]))
    return out


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _quantile(sorted_values: list[float], frac: float, population: int) -> float | None:
    """Time by which `frac` of `population` finished (None if not reached)."""
    need = max(1, int(population * frac + 0.999999))
    return sorted_values[need - 1] if len(sorted_values) >= need else None


def _med(values: list) -> float | None:
    values = [v for v in values if isinstance(v, (int, float))]
    return median(values) if values else None


def collect_run(run_dir: Path) -> dict:
    """Load one Shadow output directory into a summary dict."""
    meta = _load_json(run_dir / "run-meta.json")
    nodes = _load_json(run_dir / "nodes.json")
    hosts: dict[str, dict] = {}
    published: dict[str, int] = {}
    for name, path in iter_host_logs(run_dir):
        role = (nodes.get(name) or {}).get("role") or ("l1" if name.startswith("l1") else "l2")
        rec: dict = {"role": role, "proofs": [], "all_subnets_ms": None,
                     "aggregate_ms": None, "sent": None, "rcvd": None,
                     "redundant_proofs": 0, "duplicate_chunks": 0, "declined": 0,
                     "published_ms": None}
        for line in path.read_text(errors="replace").splitlines():
            ev = parse_event_line(line)
            if ev is None:
                continue
            kind = ev["kind"]
            if kind == "proof_published":
                rec["published_ms"] = ev["t_ms"]
                published[str(ev.get("hash"))] = ev["t_ms"]
            elif kind == "proof_complete":
                rec["proofs"].append((ev["t_ms"], str(ev.get("hash")), ev.get("subnet")))
            elif kind == "all_subnets_complete":
                rec["all_subnets_ms"] = ev["t_ms"]
            elif kind == "aggregate_complete":
                rec["aggregate_ms"] = ev["t_ms"]
            elif kind == "bytes":
                rec["sent"], rec["rcvd"] = ev.get("tx"), ev.get("rx")
            elif kind == "run_end":
                for key in ("redundant_proofs", "duplicate_chunks", "declined"):
                    rec[key] = int(ev.get(key) or 0)
        hosts[name] = rec

    t0 = min(published.values()) if published else 0
    l2 = {n: h for n, h in hosts.items() if h["role"] == "l2"}
    l1 = {n: h for n, h in hosts.items() if h["role"] == "l1"}

    def delays(key: str) -> list[float]:
        return sorted(max(0, h[key] - t0) for h in l2.values() if h[key] is not None)

    agg = delays("aggregate_ms")
    col = delays("all_subnets_ms")
    proof_latency = sorted(t - published[h] for rec in l2.values()
                           for t, h, _ in rec["proofs"] if h in published)
    gaps = [h["aggregate_ms"] - h["all_subnets_ms"] for h in l2.values()
            if h["aggregate_ms"] is not None and h["all_subnets_ms"] is not None]
    # Distinct proofs L2s chose per subnet: how concentrated the choice is.
    chosen: dict = {}
    for rec in l2.values():
        for _, h, subnet in rec["proofs"]:
            chosen.setdefault(subnet, set()).add(h)

    subnets = int(meta.get("subnets") or len(chosen) or 0)
    proof_bytes = int(meta.get("proof_size_kib") or 0) * 1024
    ideal_rx = subnets * proof_bytes
    l2_rx_med = _med([h["rcvd"] for h in l2.values()])
    n_l2 = len(l2)
    return {
        "dir": str(run_dir.resolve()),
        "label": str(meta.get("title") or meta.get("mode") or run_dir.name),
        "mode": meta.get("mode"),
        "seed": meta.get("seed"),
        "run_index": meta.get("run_index"),
        "meta": meta,
        "n_l1": len(l1),
        "n_l2": n_l2,
        "l1_published": sum(1 for h in l1.values() if h["published_ms"] is not None),
        "t0_ms": t0,
        "aggregated": len(agg),
        "collected": len(col),
        "agg_delays_ms": agg,
        "col_delays_ms": col,
        "agg_t50_ms": _quantile(agg, 0.50, n_l2),
        "agg_t95_ms": _quantile(agg, 0.95, n_l2),
        "agg_max_ms": agg[-1] if len(agg) == n_l2 and agg else None,
        "col_t50_ms": _quantile(col, 0.50, n_l2),
        "col_t95_ms": _quantile(col, 0.95, n_l2),
        "agg_gap_median_ms": _med(gaps),
        "proof_latency_median_ms": _med(proof_latency),
        "proof_latency_p95_ms": _quantile(proof_latency, 0.95, len(proof_latency) or 1),
        "l2_rx_median": l2_rx_med,
        "l2_tx_median": _med([h["sent"] for h in l2.values()]),
        "l1_tx_median": _med([h["sent"] for h in l1.values()]),
        "ideal_l2_rx": ideal_rx,
        "redundancy": (l2_rx_med / ideal_rx) if (l2_rx_med and ideal_rx) else None,
        "redundant_proofs_median": _med([h["redundant_proofs"] for h in l2.values()]),
        "duplicate_chunks_median": _med([h["duplicate_chunks"] for h in l2.values()]),
        "declined_median": _med([h["declined"] for h in l2.values()]),
        "proofs_per_subnet": (sum(len(v) for v in chosen.values()) / len(chosen))
        if chosen else None,
        "hosts": {n: {k: h[k] for k in ("role", "sent", "rcvd", "all_subnets_ms",
                                         "aggregate_ms")} for n, h in hosts.items()},
    }


# ── CLI summary ──────────────────────────────────────────────────────────────

def _ms(v) -> str:
    return "NA" if v is None else f"{v:.0f} ms"


def _kib(v) -> str:
    return "NA" if v is None else f"{v / 1024:.0f} KiB"


def print_summary(run: dict) -> None:
    n = run["n_l2"]
    print(f"── {run['label']}  ({run['dir']})")
    print(f"   L1 published: {run['l1_published']}/{run['n_l1']}   "
          f"L2 collected: {run['collected']}/{n}   aggregated: {run['aggregated']}/{n}")
    print(f"   aggregate  t50: {_ms(run['agg_t50_ms'])}  t95: {_ms(run['agg_t95_ms'])}  "
          f"max: {_ms(run['agg_max_ms'])}")
    print(f"   collection t50: {_ms(run['col_t50_ms'])}  t95: {_ms(run['col_t95_ms'])}  "
          f"aggregation tail (median): {_ms(run['agg_gap_median_ms'])}")
    print(f"   per-proof latency median: {_ms(run['proof_latency_median_ms'])}  "
          f"p95: {_ms(run['proof_latency_p95_ms'])}")
    red = "NA" if run["redundancy"] is None else f"{run['redundancy']:.2f}x"
    pps = "NA" if run["proofs_per_subnet"] is None else f"{run['proofs_per_subnet']:.2f}"
    print(f"   L2 rx median: {_kib(run['l2_rx_median'])} "
          f"(ideal {_kib(run['ideal_l2_rx'])}, {red})   "
          f"L1 tx median: {_kib(run['l1_tx_median'])}")
    print(f"   per L2 (median): redundant proofs {run['redundant_proofs_median']}, "
          f"duplicate chunks {run['duplicate_chunks_median']}, "
          f"declined {run['declined_median']};  distinct proofs used per subnet: {pps}")


# ── history ──────────────────────────────────────────────────────────────────

def load_history(out_dir: Path) -> list[dict]:
    try:
        data = json.loads((out_dir / HISTORY_NAME).read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def snapshot_identity(snap: dict) -> tuple:
    return (str(Path(snap["dir"]).resolve()), snap.get("seed"), snap.get("run_index"))


def make_snapshot(run: dict) -> dict:
    snap = dict(run)
    snap["recorded_at"] = datetime.now(timezone.utc).isoformat()
    return snap


def update_history(primary: Path, extras: list[Path], append: bool) -> list[dict]:
    history = load_history(primary)
    known = {snapshot_identity(r) for r in history}
    dirs = [primary, *extras] if (append or not history) else extras
    for path in dirs:
        run = collect_run(path)
        print_summary(run)
        snap = make_snapshot(run)
        if path == primary and append:
            history.append(snap)
        elif snapshot_identity(snap) not in known:
            history.append(snap)
        known.add(snapshot_identity(snap))
    (primary / HISTORY_NAME).write_text(json.dumps(history, indent=2) + "\n")
    return history


# ── HTML ─────────────────────────────────────────────────────────────────────

PALETTE = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2", "#be185d",
           "#4d7c0f"]


def svg_cdf(series: list[tuple[str, str, list[float], int]], title: str) -> str:
    """Step CDFs; each series is (label, color, sorted delays ms, population)."""
    w, h, pl, pr, pt, pb = 640, 320, 56, 16, 28, 44
    xmax = max((d[-1] for _, _, d, _ in series if d), default=1000) * 1.05 or 1000
    sx = lambda v: pl + (w - pl - pr) * v / xmax  # noqa: E731
    sy = lambda f: pt + (h - pt - pb) * (1 - f)  # noqa: E731
    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="{escape(title)}">',
             f'<text x="{pl}" y="18" class="t">{escape(title)}</text>']
    for i in range(6):
        f = i / 5
        parts.append(f'<line x1="{pl}" x2="{w - pr}" y1="{sy(f):.1f}" y2="{sy(f):.1f}" class="g"/>'
                     f'<text x="{pl - 6}" y="{sy(f) + 4:.1f}" class="a" text-anchor="end">'
                     f'{int(f * 100)}%</text>')
        x = xmax * f
        parts.append(f'<text x="{sx(x):.1f}" y="{h - pb + 18}" class="a" text-anchor="middle">'
                     f'{x / 1000:.1f}s</text>')
    parts.append(f'<text x="{(w + pl) / 2}" y="{h - 6}" class="a" text-anchor="middle">'
                 'time since first proof published</text>')
    for label, color, delays, pop in series:
        if not delays or not pop:
            continue
        pts = [(sx(0), sy(0))]
        for k, d in enumerate(delays, 1):
            pts += [(sx(d), sy((k - 1) / pop)), (sx(d), sy(k / pop))]
        pts.append((sx(xmax), sy(len(delays) / pop)))
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        parts.append(f'<polyline points="{path}" fill="none" stroke="{color}" '
                     f'stroke-width="2"><title>{escape(label)}</title></polyline>')
    parts.append("</svg>")
    return "".join(parts)


def write_html(runs: list[dict], out_path: Path) -> None:
    cols = [("run", None), ("mode", None), ("seed", None), ("aggregated", None),
            ("agg t50", "agg_t50_ms"), ("agg t95", "agg_t95_ms"), ("agg max", "agg_max_ms"),
            ("collect t50", "col_t50_ms"), ("collect t95", "col_t95_ms"),
            ("agg tail", "agg_gap_median_ms"), ("proof latency", "proof_latency_median_ms"),
            ("L2 rx", "l2_rx_median"), ("redundancy", "redundancy"),
            ("dup chunks", "duplicate_chunks_median"), ("proofs/subnet", "proofs_per_subnet")]
    rows = []
    series_agg, series_col = [], []
    for i, run in enumerate(runs):
        color = PALETTE[i % len(PALETTE)]
        label = f"{run['label']} #{run.get('seed')}"
        series_agg.append((label, color, run.get("agg_delays_ms") or [], run["n_l2"]))
        series_col.append((label, color, run.get("col_delays_ms") or [], run["n_l2"]))
        cells = [f'<span class="sw" style="background:{color}"></span>{escape(run["label"])}',
                 escape(str(run.get("mode"))), escape(str(run.get("seed"))),
                 f'{run["aggregated"]}/{run["n_l2"]}']
        for _, key in cols[4:]:
            v = run.get(key)
            if key in ("l2_rx_median",):
                cells.append(_kib(v))
            elif key in ("redundancy", "proofs_per_subnet"):
                cells.append("NA" if v is None else f"{v:.2f}")
            elif key in ("duplicate_chunks_median",):
                cells.append("NA" if v is None else f"{v:g}")
            else:
                cells.append(_ms(v))
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    head = "".join(f"<th>{escape(c)}</th>" for c, _ in cols)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proof Broadcast Runs</title>
<style>
:root {{ --bg:#fff; --fg:#111827; --muted:#6b7280; --line:#e5e7eb; }}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{ --bg:#0b0f17; --fg:#e5e7eb; --muted:#9ca3af; --line:#1f2937; }}
}}
:root[data-theme="dark"] {{ --bg:#0b0f17; --fg:#e5e7eb; --muted:#9ca3af; --line:#1f2937; }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.45 system-ui, sans-serif;
  margin:0 auto; padding:24px 16px; max-width:1200px; }}
h1 {{ font-size:20px; margin:0 0 4px; }} p {{ color:var(--muted); margin:0 0 16px; }}
.wrap {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; }}
th, td {{ padding:6px 8px; border-bottom:1px solid var(--line); text-align:right;
  white-space:nowrap; font-variant-numeric:tabular-nums; }}
th:first-child, td:first-child {{ text-align:left; }}
th {{ color:var(--muted); font-weight:600; }}
.sw {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; }}
.charts {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));
  gap:16px; margin-top:24px; }}
svg {{ width:100%; height:auto; }} svg .g {{ stroke:var(--line); }}
svg .a {{ fill:var(--muted); font-size:11px; }} svg .t {{ fill:var(--fg); font-size:13px; font-weight:600; }}
</style></head><body>
<h1>Proof broadcast runs</h1>
<p>L2 provers collect one proof per subnet, then aggregate with 2→1 recursion.
Times are relative to the first L1 publish. "agg tail" is the median time from
holding every subnet to finishing the aggregate. "redundancy" is the median L2 rx
over subnets × proof size.</p>
<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="charts">
<div>{svg_cdf(series_agg, "L2 aggregate complete (CDF)")}</div>
<div>{svg_cdf(series_col, "L2 holds one proof per subnet (CDF)")}</div>
</div></body></html>
"""
    out_path.write_text(html)


def serve(directory: Path, port: int) -> None:
    handler = lambda *a, **k: SimpleHTTPRequestHandler(*a, directory=str(directory), **k)  # noqa: E731
    with ThreadingHTTPServer(("0.0.0.0", port), handler) as httpd:
        print(f"serving http://0.0.0.0:{port}/{HTML_NAME}  (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("dirs", nargs="+", type=Path)
    ap.add_argument("--append", action="store_true",
                    help="append the first DIR's current run to its history")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=SERVE_PORT)
    args = ap.parse_args()
    primary = args.dirs[0].resolve()
    if not primary.is_dir():
        sys.exit(f"not a directory: {primary}")
    history = update_history(primary, [d.resolve() for d in args.dirs[1:]], args.append)
    write_html(history, primary / HTML_NAME)
    print(f"wrote {primary / HTML_NAME} ({len(history)} runs)")
    if args.serve:
        serve(primary, args.port)


if __name__ == "__main__":
    main()
