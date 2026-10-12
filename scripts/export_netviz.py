#!/usr/bin/env python3
"""Export one Shadow run as a `proof-broadcast` NDJSON trace for NetVis.

Line 1 is the header (`decoderName: "proof-broadcast"`, nodes with roles,
observed peer links with their Shadow latency, run metadata). Every other line
is one event with `t` (and `arrival` for transfers) in microseconds since the
first L1 publish.

Wire transfers come from the patched gossipsub trace hook (`wire_send` at
stream write, `wire_recv` at stream read, both tagged with the proof's subnet,
prover and committee `mask`). Sends and receives are matched per (sender,
receiver, message hash) in order. Each matched transfer is classified from
what the receiver did with it:

- `proof`    whole proof the L2 accepted (first one for its committees);
- `chunk`    partial body that added at least one new chunk;
- `announce` metadata-only partial (an L1/L2 advertising or requesting);
- `wasted`   whole proof for already-claimed committees, a gossipsub
             duplicate, or a partial body whose chunks were all already held.

Intermediate aggregates published by L2s (`subnet=65535`, `prover` = the
L2's index, `mask` = committees) are classified the same way; transfers
carry `mask` so the viewer can tell them apart.

`gossipsub-chunked` messages (topic `/proofs_chunked/1`, tagged `index=`)
are `chunk` if it is the receiver's first copy of that chunk and the receiver
used that proof (it completed first for its committees), else `wasted`.

Usage:
  python3 scripts/export_netviz.py shadow-output [destination.ndjson]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import iter_host_logs, parse_event_line  # noqa: E402

APP_KINDS = {
    "proof_published", "proof_committed", "proof_declined", "chunk_received",
    "proof_received", "proof_complete", "all_subnets_complete", "aggregation_started",
    "aggregation_done", "aggregate_complete",
    "intermediate_published", "intermediate_committed", "intermediate_declined",
    "intermediate_chunk_received", "intermediate_received", "intermediate_complete",
    "item_dropped", "proof_unused", "intermediate_unused",
}
DEFAULT_NAME = "proof-broadcast.netviz.ndjson"
AGGREGATE_SUBNET = 65535  # proof::AGGREGATE_SUBNET


def proof_key(ev: dict) -> tuple[int, int, int]:
    """(subnet, prover, committee mask). Subnet-proof events and older traces
    carry no mask; a subnet proof's mask is its own subnet's bit."""
    subnet, prover = int(ev.get("subnet", AGGREGATE_SUBNET)), int(ev.get("prover", -1))
    mask = ev.get("mask")
    if mask is None:
        mask = 1 << subnet if 0 <= subnet < 64 else 0
    return subnet, prover, int(mask)


def committee_list(mask: int) -> str:
    """`0-3-5` as in the node's event lines (`none` when empty)."""
    return "-".join(str(s) for s in range(64) if mask >> s & 1) or "none"


def parse_rate(value: str) -> float:
    amount, unit = value.split()
    return float(amount) * {"Kbit": .001, "Mbit": 1, "Gbit": 1000}[unit]


def edge_latencies(run: Path, links: set[tuple[int, int]],
                   gml_index: dict[str, int], index: dict[str, int]) -> dict[tuple[int, int], int]:
    """Shadow edge latency (ms) for each observed link, keyed by trace indices."""
    by_gml = {v: index[k] for k, v in gml_index.items() if k in index}
    result: dict[tuple[int, int], int] = {}
    fields: dict[str, str] = {}
    in_edge = False
    for line in (run / "topology.gml").read_text().splitlines():
        stripped = line.strip()
        if stripped == "edge [":
            in_edge, fields = True, {}
        elif in_edge and stripped == "]":
            in_edge = False
            a, b = by_gml.get(int(fields.get("source", -1))), by_gml.get(int(fields.get("target", -1)))
            if a is not None and b is not None and a != b:
                key = (min(a, b), max(a, b))
                if key in links:
                    result[key] = int(fields["latency"].split()[0])
        elif in_edge:
            key, _, value = stripped.partition(" ")
            fields[key] = value.strip('"')
    return result


def gml_node_ids(run: Path) -> dict[str, int]:
    """Host name -> GML node id (the launcher's node index)."""
    ids: dict[str, int] = {}
    current: int | None = None
    for line in (run / "topology.gml").read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("id "):
            current = int(stripped.split()[1])
        elif stripped.startswith("label ") and current is not None:
            ids[stripped.split(None, 1)[1].strip('"')] = current
    return ids


def time_us(ev: dict) -> int:
    return int(ev["t_us"]) if "t_us" in ev else int(ev["t_ms"]) * 1000


def export(run: Path, output: Path) -> dict[str, int]:
    meta = json.loads((run / "run-meta.json").read_text()) if (run / "run-meta.json").is_file() else {}
    nodes_meta = json.loads((run / "nodes.json").read_text())
    peers_path = run / "peers.json"
    if not peers_path.is_file():
        raise ValueError(f"{peers_path} missing: wire events cannot be attributed to hosts")
    peers = {p["name"]: p for p in json.loads(peers_path.read_text())["peers"]}
    host_of_peer = {p["peer_id"]: name for name, p in peers.items()}

    logs = iter_host_logs(run)
    if not logs:
        raise ValueError(f"no host logs in {run}")
    # L1 provers first (by subnet), then L2s: a stable, readable node order.
    logs.sort(key=lambda item: (nodes_meta.get(item[0], {}).get("role") != "l1", item[0]))
    names = [name for name, _ in logs]
    index = {name: i for i, name in enumerate(names)}

    nodes = []
    for name in names:
        info = nodes_meta.get(name, {})
        props: dict = {"role": info.get("role", "l2"), "country": info.get("region", "")}
        if info.get("up"):
            props["upload_bw_mbps"] = parse_rate(info["up"])
            props["download_bw_mbps"] = parse_rate(info["down"])
        if info.get("role") == "l1":
            props["subnet"] = info.get("subnet")
            props["prover"] = info.get("prover")
            props["publish_delay_ms"] = info.get("publish_delay_ms")
        elif info.get("prover") is not None:
            # Labels the intermediate aggregates this L2 publishes.
            props["l2_index"] = info.get("prover")
        nodes.append({"name": name, "props": props})

    events: list[dict] = []
    sends: dict[tuple[str, str, str], deque[dict]] = defaultdict(deque)
    receives: list[dict] = []
    # Receiver-side outcomes used to classify transfers, keyed by
    # (receiver, sender peer, subnet, prover, mask).
    accepted: set[tuple] = set()          # gossipsub proofs the L2 took
    chunk_outcomes: dict[tuple, deque[int]] = defaultdict(deque)
    used: set[tuple] = set()              # (receiver, subnet, prover, mask) it used
    seen_chunks: set[tuple] = set()       # gossipsub-chunked copies already received

    for name, path in logs:
        node = index[name]
        for line in path.read_text(errors="replace").splitlines():
            ev = parse_event_line(line)
            if ev is None:
                continue
            kind = ev["kind"]
            if kind == "wire_send" and "subnet" in ev:
                sends[(name, str(ev["peer"]), str(ev["id"]))].append(ev)
            elif kind == "wire_recv" and "subnet" in ev:
                ev["node"] = node
                receives.append(ev)
            elif kind in APP_KINDS:
                ev["node"] = node
                if "from" in ev:
                    ev["from_node"] = index.get(host_of_peer.get(str(ev["from"]), ""), -1)
                if kind in ("proof_received", "intermediate_received") and not ev.get("redundant"):
                    accepted.add((node, str(ev["from"]), *proof_key(ev)))
                if kind in ("chunk_received", "intermediate_chunk_received") and "index" not in ev:
                    key = (node, str(ev["from"]), *proof_key(ev))
                    chunk_outcomes[key].append(int(ev.get("added", 0)))
                if kind in ("proof_complete", "intermediate_complete"):
                    used.add((node, *proof_key(ev)))
                events.append(ev)

    for queue in sends.values():
        ordered = sorted(queue, key=time_us)
        queue.clear()
        queue.extend(ordered)

    stats = defaultdict(int)
    for ev in sorted(receives, key=time_us):
        receiver = names[ev["node"]]
        source = host_of_peer.get(str(ev.get("peer")))
        queue = sends.get((source, peers[receiver]["peer_id"], str(ev["id"]))) if source else None
        if not queue or time_us(queue[0]) > time_us(ev):
            stats["unmatched_receives"] += 1
            continue
        sent = queue.popleft()
        subnet, prover, mask = proof_key(ev)
        key = (ev["node"], str(ev["peer"]), subnet, prover, mask)
        if "index" in ev:
            copy = (ev["node"], subnet, prover, mask, int(ev["index"]))
            first = copy not in seen_chunks
            seen_chunks.add(copy)
            layer = "chunk" if first and (ev["node"], subnet, prover, mask) in used else "wasted"
        elif "body" not in ev:
            layer = "proof" if key in accepted else "wasted"
            accepted.discard(key)  # later identical copies are duplicates
        elif int(ev["body"]) == 0:
            layer = "announce"
        else:
            outcomes = chunk_outcomes.get(key)
            added = outcomes.popleft() if outcomes else 0
            layer = "chunk" if added > 0 else "wasted"
        stats[layer] += 1
        events.append({"kind": "transfer", "node": index[source], "to": ev["node"],
                       "t_us": time_us(sent), "arrival_us": time_us(ev),
                       "bytes": int(ev["bytes"]), "layer": layer,
                       "subnet": subnet, "prover": prover, "mask": mask,
                       # JS numbers cannot hold a 64-bit mask; the viewer
                       # reads this list instead.
                       "committees": committee_list(mask)})
    stats["unmatched_sends"] = sum(map(len, sends.values()))

    published = [time_us(e) for e in events if e["kind"] == "proof_published"]
    if not published:
        raise ValueError(f"no proof_published events in {run}")
    origin_us = min(published)
    for ev in events:
        ev["t"] = time_us(ev) - origin_us
        if "arrival_us" in ev:
            ev["arrival"] = ev.pop("arrival_us") - origin_us
        for key in ("t_us", "t_ms", "from"):
            ev.pop(key, None)
    events.sort(key=lambda e: (e["t"], e["node"]))

    links = {(min(e["node"], e["to"]), max(e["node"], e["to"]))
             for e in events if e["kind"] == "transfer"}
    latency = edge_latencies(run, links, gml_node_ids(run), index)
    first_l1 = min((i for i, n in enumerate(nodes) if n["props"]["role"] == "l1"), default=0)
    header = {
        "v": 1, "decoderName": "proof-broadcast", "nodes": nodes,
        "edges": [{"source": a, "target": b, "latency": latency.get((a, b), 0) * 1000}
                  for a, b in sorted(links)],
        "meta": {**meta, "originNode": first_l1,
                 "l1Count": sum(1 for n in nodes if n["props"]["role"] == "l1"),
                 "l2Count": sum(1 for n in nodes if n["props"]["role"] == "l2")},
    }
    with output.open("w") as stream:
        stream.write(json.dumps(header) + "\n")
        for ev in events:
            stream.write(json.dumps(ev) + "\n")
    return {"events": len(events), **stats}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run", type=Path, help="Shadow output directory")
    parser.add_argument("output", type=Path, nargs="?", help="destination .ndjson file")
    args = parser.parse_args()
    destination = args.output or args.run / DEFAULT_NAME
    print(f"{destination}: {export(args.run, destination)}")


if __name__ == "__main__":
    main()
