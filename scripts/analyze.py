#!/usr/bin/env python3
"""Parse proof-broadcast-tree EVENT logs into a CLI summary and a self-contained HTML page.

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
STDOUT_GLOB = "proof-broadcast-tree.*.stdout"


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
        matches = sorted(host.glob(STDOUT_GLOB)) if host.is_dir() else []
        if matches:
            out.append((host.name, matches[0]))
    return out


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _quantile(sorted_values: list[float], frac: float, population: int) -> float | None:
    """Time by which `frac` of `population` finished (None if not reached)."""
    need = max(1, int(population * frac + 0.999999))
    return sorted_values[need - 1] if len(sorted_values) >= need else None


def _med(values: list) -> float | None:
    values = [v for v in values if isinstance(v, (int, float))]
    return median(values) if values else None


RUN_END_COUNTERS = ("declined", "haves_sent", "haves_received", "chunk_requests",
                    "chunk_failures", "chunks_received", "duplicate_chunks",
                    "chunks_served", "chunks_served_partial", "chunks_missing",
                    "chunks_refused", "fanout_peak")


def collect_run(run_dir: Path) -> dict:
    """Load one Shadow output directory into a summary dict."""
    meta = _load_json(run_dir / "run-meta.json") or {}
    tree = _load_json(run_dir / "tree.json") or []
    hosts: dict[str, dict] = {}
    published: dict[str, int] = {}       # subnet proof hash -> publish time
    produced: dict[str, int] = {}        # aggregate hash -> production time
    for name, path in iter_host_logs(run_dir):
        role = "l1" if name.startswith("l1-") else "l2"
        rec: dict = {"role": role, "node": None, "level": None, "root": False, "served": [],
                     "inputs": [], "inputs_ms": None, "node_agg_ms": None,
                     "aggregate_ms": None, "published_ms": None,
                     "sent": None, "rcvd": None, "rx_data": None,
                     **{key: 0 for key in RUN_END_COUNTERS}}
        for line in path.read_text(errors="replace").splitlines():
            ev = parse_event_line(line)
            if ev is None:
                continue
            kind = ev["kind"]
            if kind == "tree_assigned":
                rec["node"], rec["level"] = ev.get("node"), ev.get("level")
                rec["root"] = bool(ev.get("root"))
            elif kind == "proof_published":
                rec["published_ms"] = ev["t_ms"]
                published[str(ev.get("hash"))] = ev["t_ms"]
            elif kind in ("proof_complete", "intermediate_complete"):
                rec["inputs"].append((ev["t_ms"], str(ev.get("hash"))))
            elif kind == "inputs_complete":
                rec["inputs_ms"] = ev["t_ms"]
            elif kind == "node_aggregate_complete":
                rec["node_agg_ms"] = ev["t_ms"]
                produced[str(ev.get("hash"))] = ev["t_ms"]
            elif kind == "aggregate_complete":
                rec["aggregate_ms"] = ev["t_ms"]
            elif kind == "proof_served":
                rec["served"].append(int(ev.get("peers") or 0))
            elif kind == "bytes":
                rec["sent"], rec["rcvd"] = ev.get("tx"), ev.get("rx")
                rec["rx_data"] = ev.get("rx_data")
            elif kind == "run_end":
                for key in RUN_END_COUNTERS:
                    rec[key] = int(ev.get(key) or 0)
        hosts[name] = rec

    t0 = min(published.values()) if published else 0
    l2 = {n: h for n, h in hosts.items() if h["role"] == "l2"}
    l1 = {n: h for n, h in hosts.items() if h["role"] == "l1"}
    n_l2 = len(l2)

    def delays(recs, key: str) -> list[float]:
        return sorted(max(0, h[key] - t0) for h in recs if h[key] is not None)

    root = [h for h in l2.values() if h["root"]]
    root_d = delays(root, "aggregate_ms")
    node_d = delays(l2.values(), "node_agg_ms")

    depth = int(meta.get("tree_depth") or 0) or (
        max((h["level"] for h in l2.values() if h["level"] is not None), default=-1) + 1)
    nodes_at = {lv: [t["id"] for t in tree if t.get("level") == lv] for lv in range(depth)}
    levels = []
    for lv in range(depth):
        members = [h for h in l2.values() if h["level"] == lv]
        done = delays(members, "node_agg_ms")
        # A level is ready once every node of it has produced an aggregate.
        firsts = {}
        for h in members:
            if h["node_agg_ms"] is not None:
                t = h["node_agg_ms"] - t0
                firsts[h["node"]] = min(t, firsts.get(h["node"], t))
        ids = nodes_at.get(lv) or sorted({h["node"] for h in members})
        ready = max(firsts[i] for i in ids) if ids and all(i in firsts for i in ids) else None
        levels.append({
            "level": lv,
            "nodes": len(ids),
            "members": len(members),
            "done": len(done),
            "first_ms": done[0] if done else None,
            "ready_ms": ready,
            "t50_ms": _quantile(done, 0.50, len(members)) if members else None,
            "inputs_t50_ms": _quantile(delays(members, "inputs_ms"), 0.50, len(members))
            if members else None,
            "rx_median": _med([h["rcvd"] for h in members]),
            "delays_ms": done,
        })

    # Time from a proof being available (published / produced) to an input
    # holder having all of it: one hop of the pull.
    hop = sorted(t - (published.get(h) or produced.get(h)) for rec in l2.values()
                 for t, h in rec["inputs"] if h in published or h in produced)
    proof_bytes = int(meta.get("proof_size_kib") or 0) * 1024
    l1_tx_med = _med([h["sent"] for h in l1.values()])

    def counter(key: str) -> list[int]:
        return [h[key] for h in l2.values()]

    # Fan-out: distinct peers each served proof reached (over the whole run),
    # and the most peers any proof was served to at once.
    per_proof = sorted(n for h in hosts.values() for n in h["served"])
    total_served = sum(h["chunks_served"] for h in hosts.values())

    return {
        "dir": str(run_dir.resolve()),
        "label": str(meta.get("title") or run_dir.name),
        "seed": meta.get("seed"),
        "run_index": meta.get("run_index"),
        "meta": meta,
        "n_l1": len(l1),
        "n_l2": n_l2,
        "l1_published": sum(1 for h in l1.values() if h["published_ms"] is not None),
        "t0_ms": t0,
        "arity": meta.get("aggregation_arity"),
        "tree_nodes": meta.get("tree_nodes") or len(tree) or None,
        "tree_depth": depth,
        "empty_tree_nodes": meta.get("empty_tree_nodes") or [],
        "n_root": len(root),
        "root_done": len(root_d),
        "root_delays_ms": root_d,
        # The headline: when the first global proof exists.
        "root_first_ms": root_d[0] if root_d else None,
        "root_t50_ms": _quantile(root_d, 0.50, len(root)) if root else None,
        "root_max_ms": root_d[-1] if root and len(root_d) == len(root) else None,
        "node_done": len(node_d),
        "node_delays_ms": node_d,
        "node_t50_ms": _quantile(node_d, 0.50, n_l2),
        "stalled_l2": n_l2 - len(node_d),
        "levels": levels,
        "hop_latency_median_ms": _med(hop),
        "hop_latency_p95_ms": _quantile(hop, 0.95, len(hop) or 1),
        "l1_tx_median": l1_tx_med,
        "l1_amplification": (l1_tx_med / proof_bytes) if (l1_tx_med and proof_bytes) else None,
        "l2_rx_median": _med([h["rcvd"] for h in l2.values()]),
        "l2_tx_median": _med([h["sent"] for h in l2.values()]),
        "declined_median": _med(counter("declined")),
        "chunk_failures_total": sum(counter("chunk_failures")),
        "duplicate_chunks_total": sum(counter("duplicate_chunks")),
        "chunks_missing_total": sum(h["chunks_missing"] for h in hosts.values()),
        "fanout": meta.get("fanout"),
        "fanout_peak": max((h["fanout_peak"] for h in hosts.values()), default=0),
        "peers_per_proof_median": _med(per_proof),
        "peers_per_proof_max": per_proof[-1] if per_proof else None,
        "chunks_refused_total": sum(h["chunks_refused"] for h in hosts.values()),
        # Share of served chunks relayed before the relay held the whole proof.
        "cut_through_share": (sum(h["chunks_served_partial"] for h in hosts.values())
                              / total_served) if total_served else None,
        "l2_relaying": sum(1 for h in l2.values() if h["chunks_served"]),
        "hosts": {n: {k: h[k] for k in ("role", "node", "level", "sent", "rcvd",
                                         "node_agg_ms", "aggregate_ms")}
                  for n, h in hosts.items()},
    }


# ── CLI summary ──────────────────────────────────────────────────────────────

def _ms(v) -> str:
    return "NA" if v is None else f"{v:.0f} ms"


def _kib(v) -> str:
    return "NA" if v is None else f"{v / 1024:.0f} KiB"


def print_summary(run: dict) -> None:
    n = run["n_l2"]
    print(f"── {run['label']}  ({run['dir']})")
    print(f"   tree: {run['tree_nodes']} nodes, depth {run['tree_depth']}, "
          f"arity {run['arity']}"
          + (f";  EMPTY tree nodes: {run['empty_tree_nodes']}" if run["empty_tree_nodes"] else ""))
    print(f"   L1 published: {run['l1_published']}/{run['n_l1']}   "
          f"L2 node aggregate done: {run['node_done']}/{n}   "
          f"root with global proof: {run['root_done']}/{run['n_root']}")
    print(f"   global proof  first: {_ms(run['root_first_ms'])}  "
          f"root t50: {_ms(run['root_t50_ms'])}  root max: {_ms(run['root_max_ms'])}")
    for lv in run["levels"]:
        print(f"   level {lv['level']}: {lv['nodes']} nodes, {lv['members']} L2s  "
              f"first {_ms(lv['first_ms'])}  ready {_ms(lv['ready_ms'])}  "
              f"t50 {_ms(lv['t50_ms'])}  (inputs t50 {_ms(lv['inputs_t50_ms'])}, "
              f"rx median {_kib(lv['rx_median'])})")
    amp = "NA" if run["l1_amplification"] is None else f"{run['l1_amplification']:.1f}x"
    print(f"   hop latency median: {_ms(run['hop_latency_median_ms'])}  "
          f"p95: {_ms(run['hop_latency_p95_ms'])}")
    print(f"   L1 tx median: {_kib(run['l1_tx_median'])} ({amp} proof)   "
          f"L2 rx median: {_kib(run['l2_rx_median'])}   L2 tx median: {_kib(run['l2_tx_median'])}")
    cut = "NA" if run["cut_through_share"] is None else f"{run['cut_through_share']:.0%}"
    print(f"   fan-out {run['fanout']}: peak {run['fanout_peak']} at once;  peers per served "
          f"proof median {run['peers_per_proof_median']}, max {run['peers_per_proof_max']};  "
          f"L2s relaying {run['l2_relaying']}/{n};  served while still arriving {cut};  "
          f"refused (Busy) {run['chunks_refused_total']}")
    print(f"   declined/L2 median {run['declined_median']};  chunk failures "
          f"{run['chunk_failures_total']}, duplicates {run['duplicate_chunks_total']}, "
          f"missing answers {run['chunks_missing_total']}")


# ── history ──────────────────────────────────────────────────────────────────

def load_history(out_dir: Path) -> list[dict]:
    data = _load_json(out_dir / HISTORY_NAME)
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
    cols = [("run", None), ("arity", None), ("fanout", None), ("seed", None), ("tree", None),
            ("node aggs", None), ("global first", "root_first_ms"),
            ("root t50", "root_t50_ms"), ("root max", "root_max_ms"),
            ("node t50", "node_t50_ms"), ("hop latency", "hop_latency_median_ms"),
            ("L1 tx", "l1_tx_median"), ("L2 rx", "l2_rx_median"),
            ("cut-through", "cut_through_share"),
            ("chunk failures", "chunk_failures_total")]
    rows = []
    series_root, series_node = [], []
    for i, run in enumerate(runs):
        color = PALETTE[i % len(PALETTE)]
        label = f"{run['label']} #{run.get('seed')}"
        series_root.append((label, color, run.get("root_delays_ms") or [], run["n_root"]))
        series_node.append((label, color, run.get("node_delays_ms") or [], run["n_l2"]))
        tree = f"{run.get('tree_nodes')} / d{run.get('tree_depth')}"
        if run.get("empty_tree_nodes"):
            tree += f" ({len(run['empty_tree_nodes'])} empty)"
        cells = [f'<span class="sw" style="background:{color}"></span>{escape(run["label"])}',
                 escape(str(run.get("arity"))), escape(str(run.get("fanout"))),
                 escape(str(run.get("seed"))), escape(tree),
                 f'{run["node_done"]}/{run["n_l2"]}']
        for _, key in cols[6:]:
            v = run.get(key)
            if key in ("l1_tx_median", "l2_rx_median"):
                cells.append(_kib(v))
            elif key == "chunk_failures_total":
                cells.append("NA" if v is None else f"{v:g}")
            elif key == "cut_through_share":
                cells.append("NA" if v is None else f"{v:.0%}")
            else:
                cells.append(_ms(v))
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    head = "".join(f"<th>{escape(c)}</th>" for c, _ in cols)
    latest = runs[-1] if runs else None
    level_chart = ""
    if latest:
        level_series = [(f"level {lv['level']}", PALETTE[lv["level"] % len(PALETTE)],
                         lv["delays_ms"], lv["members"]) for lv in latest["levels"]]
        level_chart = svg_cdf(level_series,
                              f"Node aggregate per level — {latest['label']} #{latest.get('seed')}")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proof Tree Runs</title>
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
<h1>Proof aggregation tree runs</h1>
<p>L2 aggregators sit at the tree node their PeerId hashes to. Each tree node
merges its inputs (subnet proofs or child aggregates) with one k→1 recursion
and hands the result to its parent's aggregators. Times are relative to the
first L1 publish. "global first" is when the first root aggregator holds the
global proof; "node t50" is when half of all L2s finished their node's
aggregate; "hop latency" is the median time from a proof existing to an
aggregator that needs it holding all of it. Each proof is served to at most
"fanout" peers at a time, and relayed while it is still arriving;
"cut-through" is the share of served chunks sent before the relay held the
whole proof.</p>
<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="charts">
<div>{svg_cdf(series_root, "Root aggregators holding the global proof (CDF)")}</div>
<div>{svg_cdf(series_node, "L2 node aggregate complete (CDF)")}</div>
<div>{level_chart}</div>
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
