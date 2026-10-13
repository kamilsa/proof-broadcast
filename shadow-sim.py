#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Launch a proof-aggregation-tree simulation under Shadow.

Reads a TOML config (default `proofsim.toml`), assigns prover roles
(`subnets x provers_per_subnet` L1 provers, then `l2_provers` L2 aggregators),
asks the binary (`--dump-tree`) for the aggregation tree and every L2's tree
node (a function of its PeerId), wires peers along the tree, generates a
geo-realistic Shadow topology (`topology.gml`) and a `shadow.yaml`, then runs
the simulation either:
  - in Docker  ([run].runner = "docker"): builds an image with
    proof-broadcast-tree on top of a Shadow base image and runs Shadow in a
    container; or
  - natively   ([run].runner = "native"): builds with `cargo build --release`
    and runs a `shadow` binary from PATH.

Usage:
  uv run shadow-sim.py                      # build (if needed) + run with proofsim.toml
  uv run shadow-sim.py my.toml              # use a different config file
  uv run shadow-sim.py --dry-run            # build + generate shadow.yaml/topology.gml only
  uv run shadow-sim.py --rebuild            # force `docker build` first
  uv run shadow-sim.py --clean              # wipe shadow.data/, history and summary.html
  uv run shadow-sim.py --serve              # run, then serve the interactive summary

Results land in `<output.dir>/shadow.data/hosts/<host>/proof-broadcast-tree.1000.stdout`.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

CL_PORT = 9000  # libp2p QUIC (UDP)

BIN_NAME = "proof-broadcast-tree"
BIN_DOCKER = f"/opt/proofsim/{BIN_NAME}"
BIN_NATIVE = str(REPO_ROOT / "target" / "release" / BIN_NAME)
STDOUT_NAME = f"{BIN_NAME}.1000.stdout"

# Keep in sync with the clap defaults in src/node.rs.
DEFAULT_SUBNETS = 16
DEFAULT_PROVERS_PER_SUBNET = 4
DEFAULT_L2_PROVERS = 64
DEFAULT_PROOF_SIZE_KIB = 300
DEFAULT_CHUNK_COUNT = 64
MAX_CHUNKS = 4096  # proof::MAX_CHUNKS
MAX_SUBNETS = 64  # proof::MAX_SUBNETS (committees fit a u64 mask)
DEFAULT_PROOF_JITTER_MS = 500
DEFAULT_AGGREGATION_MS = 290  # leanVM README: 2->1 recursion 0.287 s (M4 Max)
DEFAULT_AGGREGATION_ARITY = 2
DEFAULT_MAX_INFLIGHT_PER_PEER = 64
DEFAULT_FANOUT = 8                  # peers one proof is served to at a time
DEFAULT_HAVE_INTERVAL_MS = 10       # chunk-progress announcements are batched this long
DEFAULT_REQUEST_TIMEOUT_MS = 10_000
DEFAULT_WARMUP_SECS = 15
DEFAULT_OBSERVE_SECS = 20
DEFAULT_L1_PEERS_PER_NODE = 4       # consumer-node members each L1 dials
DEFAULT_TREE_MATES_PER_NODE = 8     # node-mates each L2 dials
DEFAULT_TREE_PARENT_PEERS = 4       # parent-node members each L2 dials
DEFAULT_BANDWIDTH_UP = "25 Mbit"    # EIP-7870
DEFAULT_BANDWIDTH_DOWN = "50 Mbit"
DEFAULT_IMAGE = "proofsim-tree-shadow:local"
CONTAINER_NAME = "proofsim-tree-shadow-run"

# Inter-region round-trip latencies in milliseconds, ported from ec-sim /
# blobsim. generate_gml writes these as Shadow's edge latency.
REGIONS_LATENCY_MS: dict[str, dict[str, int]] = {
    "us-east": {"us-east": 20, "us-west": 60, "europe": 80, "asia": 150, "sa": 120, "africa": 180},
    "us-west": {"us-east": 60, "us-west": 20, "europe": 130, "asia": 110, "sa": 160, "africa": 200},
    "europe": {"us-east": 80, "us-west": 130, "europe": 15, "asia": 100, "sa": 170, "africa": 80},
    "asia": {"us-east": 150, "us-west": 110, "europe": 100, "asia": 20, "sa": 250, "africa": 160},
    "sa": {"us-east": 120, "us-west": 160, "europe": 170, "asia": 250, "sa": 25, "africa": 220},
    "africa": {"us-east": 180, "us-west": 200, "europe": 80, "asia": 160, "sa": 220, "africa": 30},
}


def log(msg: str) -> None:
    print(f"[shadow-sim] {msg}", flush=True)


def die(msg: str) -> None:
    print(f"[shadow-sim] error: {msg}", file=sys.stderr)
    sys.exit(1)


# ── config accessors ─────────────────────────────────────────────────────────

def _positive_int(section: dict, key: str, default: int, where: str = "sim") -> int:
    value = int(section.get(key, default))
    if value < 1:
        die(f"[{where}].{key} must be >= 1, got {value}")
    return value


def _nonneg_int(section: dict, key: str, default: int, where: str = "sim") -> int:
    value = int(section.get(key, default))
    if value < 0:
        die(f"[{where}].{key} must be >= 0, got {value}")
    return value


def prover_settings(sim: dict) -> dict:
    """Validated prover / proof / aggregation parameters, as run metadata."""
    subnets = _positive_int(sim, "subnets", DEFAULT_SUBNETS)
    if not 2 <= subnets <= MAX_SUBNETS:
        die(f"[sim].subnets must be in 2..{MAX_SUBNETS}, got {subnets}")
    chunks = _positive_int(sim, "chunk_count", DEFAULT_CHUNK_COUNT)
    if chunks > MAX_CHUNKS:
        die(f"[sim].chunk_count must be <= {MAX_CHUNKS}, got {chunks}")
    arity = _positive_int(sim, "aggregation_arity", DEFAULT_AGGREGATION_ARITY)
    if not 2 <= arity <= MAX_SUBNETS:
        die(f"[sim].aggregation_arity must be in 2..{MAX_SUBNETS}, got {arity}")
    return {
        "subnets": subnets,
        "provers_per_subnet": _positive_int(sim, "provers_per_subnet", DEFAULT_PROVERS_PER_SUBNET),
        "l2_provers": _positive_int(sim, "l2_provers", DEFAULT_L2_PROVERS),
        "proof_size_kib": _positive_int(sim, "proof_size_kib", DEFAULT_PROOF_SIZE_KIB),
        "chunk_count": chunks,
        "proof_jitter_ms": _nonneg_int(sim, "proof_jitter_ms", DEFAULT_PROOF_JITTER_MS),
        "aggregation_ms": _nonneg_int(sim, "aggregation_ms", DEFAULT_AGGREGATION_MS),
        "aggregation_arity": arity,
        "max_inflight_per_peer": _positive_int(sim, "max_inflight_per_peer",
                                               DEFAULT_MAX_INFLIGHT_PER_PEER),
        "request_timeout_ms": _positive_int(sim, "request_timeout_ms",
                                            DEFAULT_REQUEST_TIMEOUT_MS),
        "fanout": _positive_int(sim, "fanout", DEFAULT_FANOUT),
        "have_interval_ms": _nonneg_int(sim, "have_interval_ms", DEFAULT_HAVE_INTERVAL_MS),
        "warmup_secs": _nonneg_int(sim, "warmup_secs", DEFAULT_WARMUP_SECS),
        "observe_secs": _nonneg_int(sim, "observe_secs", DEFAULT_OBSERVE_SECS),
    }


def topology_settings(topo: dict) -> dict:
    """How many tree neighbours each node dials."""
    return {
        "l1_peers_per_node": _positive_int(topo, "l1_peers_per_node",
                                           DEFAULT_L1_PEERS_PER_NODE, "topology"),
        "tree_mates_per_node": _nonneg_int(topo, "tree_mates_per_node",
                                           DEFAULT_TREE_MATES_PER_NODE, "topology"),
        "tree_parent_peers": _positive_int(topo, "tree_parent_peers",
                                           DEFAULT_TREE_PARENT_PEERS, "topology"),
    }


def tree_size(subnets: int, arity: int) -> int:
    """Tree nodes for `subnets` leaves and fan-in `arity` (mirrors src/tree.rs:
    groups of `arity`, a trailing single item is promoted)."""
    items, nodes = subnets, 0
    while items > 1:
        groups, rest = divmod(items, arity)
        made = groups + (1 if rest > 1 else 0)
        nodes += made
        items = made + (1 if rest == 1 else 0)
    return nodes


def role_bandwidth(net: dict, role: str) -> tuple[str, str]:
    section = net.get(role, {})
    return (str(section.get("bandwidth_up", DEFAULT_BANDWIDTH_UP)),
            str(section.get("bandwidth_down", DEFAULT_BANDWIDTH_DOWN)))


# Seed offset of each role's supernode pick (own RNG streams, so topology
# draws, and the other role's pick, do not change with a fraction).
SUPERNODE_SEED_OFFSET = {"l2": 5, "l1": 6}


def assign_bandwidth(nodes: list["Node"], net: dict, seed: int) -> None:
    """Per-role bandwidth, then optional `[network.l1_supernodes]` and
    `[network.l2_supernodes]`: a seeded, exact `fraction` of that role's hosts
    gets the section's bandwidth instead."""
    for node in nodes:
        node.bandwidth_up, node.bandwidth_down = role_bandwidth(net, node.role)
    for role, offset in SUPERNODE_SEED_OFFSET.items():
        key = f"{role}_supernodes"
        section = net.get(key)
        if not section:
            continue
        fraction = float(section.get("fraction", 0.0))
        if not 0.0 <= fraction <= 1.0:
            die(f"[network.{key}].fraction must be in [0, 1], got {fraction}")
        hosts = [node for node in nodes if node.role == role]
        for node in random.Random(seed + offset).sample(hosts, round(fraction * len(hosts))):
            node.bandwidth_up, node.bandwidth_down = role_bandwidth(net, key)
            node.supernode = True


# ── nodes and topology ───────────────────────────────────────────────────────

class Node:
    """One simulated host: a Shadow host + a proof-broadcast-tree process."""

    def __init__(self, index: int, name: str, role: str, subnet: int = 0, prover: int = 0):
        self.index = index
        self.name = name
        self.role = role
        self.subnet = subnet
        self.prover = prover
        self.publish_delay_ms = 0
        self.ip = ""
        self.region = ""
        self.bandwidth_up = ""
        self.bandwidth_down = ""
        self.supernode = False
        self.peer_id = ""
        # L2: the tree node its PeerId maps to. L1: the node consuming its subnet.
        self.tree_node: int | None = None


def build_nodes(sim: dict) -> list[Node]:
    """L1 provers first (`subnet = i // provers_per_subnet`), then L2 provers."""
    p = prover_settings(sim)
    l1 = p["subnets"] * p["provers_per_subnet"]
    n = l1 + p["l2_provers"]
    width = max(3, len(str(n - 1)))
    nodes: list[Node] = []
    for i in range(l1):
        subnet, prover = divmod(i, p["provers_per_subnet"])
        nodes.append(Node(i, f"l1-s{subnet:02d}-p{prover}", "l1", subnet, prover))
    for j in range(p["l2_provers"]):
        # An L2's prover index labels the aggregates it produces.
        nodes.append(Node(l1 + j, f"l2-{j:0{width}d}", "l2", prover=j))
    base = ipaddress.ip_address("11.0.0.1")
    for node in nodes:
        node.ip = str(base + node.index)
    return nodes


def node_seed(seed: int, node: Node) -> int:
    return seed + node.index


def assign_publish_delays(nodes: list[Node], jitter_ms: int, seed: int) -> None:
    """Seeded uniform L1 publish delays in [0, jitter_ms]; separate RNG stream
    so topology draws do not change when the jitter does."""
    rng = random.Random(seed + 3)
    for node in nodes:
        if node.role == "l1":
            node.publish_delay_ms = rng.randint(0, jitter_ms) if jitter_ms > 0 else 0


def weighted_assign(weights: dict[str, float], count: int, rng: random.Random) -> list[str]:
    keys = list(weights.keys())
    vals = list(weights.values())
    return [rng.choices(keys, weights=vals, k=1)[0] for _ in range(count)]


def generate_gml(nodes: list[Node], jitter_ratio: float, packet_loss: float,
                 rng: random.Random) -> str:
    n = len(nodes)
    lines: list[str] = ["graph [", "  directed 0"]
    for node in nodes:
        lines += [
            "  node [",
            f"    id {node.index}",
            f'    host_bandwidth_up "{node.bandwidth_up}"',
            f'    host_bandwidth_down "{node.bandwidth_down}"',
            f'    label "{node.name}"',
            f'    region "{node.region}"',
            "  ]",
        ]
    for node in nodes:
        lines += ["  edge [", f"    source {node.index}", f"    target {node.index}",
                  '    latency "1 ms"', f"    packet_loss {packet_loss}", "  ]"]
    # Full inter-host mesh from the region latency matrix plus per-edge jitter.
    for i in range(n):
        ri = nodes[i].region
        for j in range(i + 1, n):
            base_ms = REGIONS_LATENCY_MS[ri].get(nodes[j].region, 200)
            jitter = base_ms * jitter_ratio * (rng.random() * 2 - 1)
            latency = max(0.5, base_ms + jitter)
            lines += ["  edge [", f"    source {i}", f"    target {j}",
                      f'    latency "{max(1, round(latency))} ms"',
                      f"    packet_loss {packet_loss}", "  ]"]
    lines.append("]")
    return "\n".join(lines) + "\n"


# ── the tree (from the binary) ───────────────────────────────────────────────

def run_binary(args: list[str], bin_path: str, image: str | None) -> str | None:
    """Run the node binary with `args` (natively or in the image); None if it
    is not available."""
    if bin_path == BIN_DOCKER:
        if not image or not image_exists(image):
            return None
        cmd = ["docker", "run", "--rm", "--platform", "linux/arm64",
               "--entrypoint", BIN_DOCKER, image, *args]
    else:
        if not Path(bin_path).is_file():
            return None
        cmd = [bin_path, *args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        die(f"{BIN_NAME} {' '.join(args[:3])}… failed: {err}")
    return result.stdout


def tree_info(nodes: list[Node], sim: dict, seed: int, bin_path: str,
              image: str | None) -> dict:
    """`--dump-tree`: the tree nodes, and every host's PeerId and tree node.
    The binary is the single source of truth for both."""
    p = prover_settings(sim)
    seeds = ",".join(str(node_seed(seed, n)) for n in nodes)
    out = run_binary(["--dump-tree", "--subnets", str(p["subnets"]),
                      "--aggregation-arity", str(p["aggregation_arity"]),
                      "--dump-peer-ids", seeds], bin_path, image)
    if out is None:
        die(f"{bin_path} not available: the tree and PeerIds come from the binary "
            "(build it first: `cargo build --release`, or the docker image)")
    return json.loads(out)


def apply_tree(nodes: list[Node], tree: dict) -> None:
    """Record PeerIds and tree positions on the hosts."""
    peers = tree["peers"]
    if len(peers) != len(nodes):
        die(f"--dump-tree returned {len(peers)} peers, expected {len(nodes)}")
    consumer = {s: t["id"] for t in tree["nodes"] for s in t["input_subnets"]}
    for node, peer in zip(nodes, peers):
        node.peer_id = peer["peer_id"]
        node.tree_node = peer["tree_node"] if node.role == "l2" else consumer[node.subnet]


def tree_members(nodes: list[Node], tree: dict) -> list[list[Node]]:
    members: list[list[Node]] = [[] for _ in tree["nodes"]]
    for node in nodes:
        if node.role == "l2":
            members[node.tree_node].append(node)
    return members


def empty_tree_nodes(nodes: list[Node], tree: dict) -> list[int]:
    return [i for i, m in enumerate(tree_members(nodes, tree)) if not m]


def wire_peers(nodes: list[Node], tree: dict, topo: dict,
               rng: random.Random) -> dict[int, list[str]]:
    """Dial along the tree: an L1 dials members of the node consuming its
    subnet; an L2 dials node-mates and members of its parent node (children
    reach it through their own parent links). Connections are two-way."""
    t = topology_settings(topo)
    members = tree_members(nodes, tree)
    out: dict[int, list[str]] = {}
    for node in nodes:
        if node.role == "l1":
            pool = members[node.tree_node]
            chosen = rng.sample(pool, min(t["l1_peers_per_node"], len(pool)))
        else:
            mates = [m for m in members[node.tree_node] if m.index != node.index]
            chosen = rng.sample(mates, min(t["tree_mates_per_node"], len(mates)))
            parent = tree["nodes"][node.tree_node]["parent"]
            if parent is not None:
                pool = members[parent]
                chosen += rng.sample(pool, min(t["tree_parent_peers"], len(pool)))
        out[node.index] = [f"/ip4/{p.ip}/udp/{CL_PORT}/quic-v1" for p in chosen]
    return out


def tree_meta(nodes: list[Node], tree: dict) -> dict:
    members = tree_members(nodes, tree)
    levels = sorted({t["level"] for t in tree["nodes"]})
    return {
        "tree_nodes": len(tree["nodes"]),
        "tree_depth": tree["depth"],
        "empty_tree_nodes": [i for i, m in enumerate(members) if not m],
        "members_per_node": [len(m) for m in members],
        "nodes_per_level": [sum(1 for t in tree["nodes"] if t["level"] == lv) for lv in levels],
    }


def build_args(node: Node, cfg: dict, peers: list[str]) -> str:
    sim = cfg["sim"]
    p = prover_settings(sim)
    parts: list[str] = [
        "--role", node.role,
        "--seed", str(node_seed(int(sim["seed"]), node)),
        "--listen-port", str(CL_PORT),
        "--subnets", str(p["subnets"]),
        "--aggregation-arity", str(p["aggregation_arity"]),
        "--proof-size-kib", str(p["proof_size_kib"]),
        "--chunk-count", str(p["chunk_count"]),
        "--aggregation-ms", str(p["aggregation_ms"]),
        "--max-inflight-per-peer", str(p["max_inflight_per_peer"]),
        "--request-timeout-ms", str(p["request_timeout_ms"]),
        "--fanout", str(p["fanout"]),
        "--have-interval-ms", str(p["have_interval_ms"]),
        "--warmup-secs", str(p["warmup_secs"]),
        "--observe-secs", str(p["observe_secs"]),
    ]
    if node.role == "l1":
        parts += ["--subnet", str(node.subnet), "--prover", str(node.prover),
                  "--publish-delay-ms", str(node.publish_delay_ms)]
    else:
        parts += ["--prover", str(node.prover)]
    for peer in peers:
        parts += ["--peer", peer]
    return " ".join(parts)


def generate_shadow_yaml(nodes: list[Node], cfg: dict, gml_path: Path,
                         peers: dict[int, list[str]], bin_path: str) -> str:
    sim = cfg["sim"]
    p = prover_settings(sim)
    stop_time = sim.get("stop_time") or f"{p['warmup_secs'] + p['observe_secs'] + 30}s"
    rust_log = str(sim.get("rust_log", "info"))
    out: list[str] = [
        "# Auto-generated by shadow-sim.py — do not edit by hand.",
        "general:",
        f"  stop_time: {stop_time}",
        "  model_unblocked_syscall_latency: true",
        "",
        "network:",
        "  use_shortest_path: true",
        "  graph:",
        "    type: gml",
        "    file:",
        f"      path: {gml_path}",
        "",
        "hosts:",
    ]
    for node in nodes:
        args = build_args(node, cfg, peers.get(node.index, []))
        out += [
            f"  {node.name}:",
            f"    network_node_id: {node.index}",
            f"    ip_addr: {node.ip}",
            f'    bandwidth_up: "{node.bandwidth_up}"',
            f'    bandwidth_down: "{node.bandwidth_down}"',
            "    processes:",
            f"    - path: {bin_path}",
            f'      args: "{args}"',
            "      start_time: 1s",
            "      expected_final_state: {exited: 0}",
            "      environment:",
            f'        RUST_LOG: "{rust_log}"',
        ]
    return "\n".join(out) + "\n"


def generate_run(cfg: dict, out_dir: Path, seed: int, bin_path: str,
                 image: str | None = None, tree: dict | None = None) -> tuple[list[Node], dict]:
    """Write topology.gml, shadow.yaml, nodes.json and peers.json for one run.
    `tree` (a `--dump-tree` document) is fetched from the binary unless given."""
    cfg["sim"]["seed"] = seed
    sim = cfg["sim"]
    net = cfg.get("network", {})
    topo = cfg.get("topology", {})
    jitter_ratio = float(net.get("jitter_ratio", 0.3))
    packet_loss = float(net.get("packet_loss", 0.0))
    region_weights = {k: float(v) for k, v in net.get("regions", {"europe": 1.0}).items()}
    unknown = set(region_weights) - set(REGIONS_LATENCY_MS)
    if unknown:
        die(f"unknown regions in [network.regions]: {sorted(unknown)}")

    nodes = build_nodes(sim)
    assign_publish_delays(nodes, prover_settings(sim)["proof_jitter_ms"], seed)
    geo_rng = random.Random(seed)
    for node, region in zip(nodes, weighted_assign(region_weights, len(nodes), geo_rng)):
        node.region = region
    assign_bandwidth(nodes, net, seed)

    if tree is None:
        tree = tree_info(nodes, sim, seed, bin_path, image)
    apply_tree(nodes, tree)
    empty = empty_tree_nodes(nodes, tree)
    if empty:
        log(f"warning: tree nodes {empty} have no aggregator (seed {seed}): their "
            "subtree never reaches the root. Use more l2_provers or another seed.")

    gml_path = out_dir / "topology.gml"
    gml_path.write_text(generate_gml(nodes, jitter_ratio, packet_loss, geo_rng))
    (out_dir / "tree.json").write_text(json.dumps(tree["nodes"], indent=2) + "\n")
    (out_dir / "nodes.json").write_text(json.dumps({
        node.name: {"role": node.role, "subnet": node.subnet if node.role == "l1" else None,
                    "prover": node.prover,
                    "publish_delay_ms": node.publish_delay_ms if node.role == "l1" else None,
                    "tree_node": node.tree_node,
                    "level": tree["nodes"][node.tree_node]["level"],
                    "committees": tree["nodes"][node.tree_node]["committees"],
                    "region": node.region,
                    "up": node.bandwidth_up, "down": node.bandwidth_down,
                    "supernode": node.supernode}
        for node in nodes
    }, indent=2))
    peers_doc = [{"name": node.name, "peer_id": node.peer_id, "role": node.role,
                  "addr": f"/ip4/{node.ip}/udp/{CL_PORT}/quic-v1"} for node in nodes]
    (out_dir / "peers.json").write_text(json.dumps({"peers": peers_doc}, indent=2) + "\n")

    peers = wire_peers(nodes, tree, topo, random.Random(seed + 1))
    (out_dir / "shadow.yaml").write_text(
        generate_shadow_yaml(nodes, cfg, gml_path, peers, bin_path))

    l1 = sum(1 for x in nodes if x.role == "l1")
    meta = tree_meta(nodes, tree)
    log(f"  {len(nodes)} hosts: {l1} L1 provers, {len(nodes) - l1} L2 aggregators; "
        f"tree: {meta['tree_nodes']} nodes, depth {meta['tree_depth']}, "
        f"aggregators per node {min(meta['members_per_node'])}..{max(meta['members_per_node'])}")
    return nodes, tree


# ── build / run ──────────────────────────────────────────────────────────────

def image_exists(image: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True).returncode == 0


def docker_build(image: str, shadow_image: str) -> None:
    log(f"building image {image} on base {shadow_image} (arm64)...")
    subprocess.run(
        ["docker", "build", "--platform", "linux/arm64",
         "-f", str(REPO_ROOT / "docker" / "Dockerfile"),
         "--build-arg", f"SHADOW_IMAGE={shadow_image}",
         "-t", image, str(REPO_ROOT)],
        check=True,
    )


def cargo_build_release() -> None:
    if shutil.which("cargo") is None:
        die("`cargo` not found in PATH — needed for the native runner.")
    log(f"building {BIN_NAME} (cargo build --release)...")
    subprocess.run(["cargo", "build", "--release"], cwd=REPO_ROOT, check=True)


def native_run_shadow(out_dir: Path) -> None:
    if shutil.which("shadow") is None:
        die("`shadow` not found in PATH. Install Shadow (https://shadow.github.io/) "
            'or use the Docker runner ([run].runner = "docker").')
    log("running Shadow natively...")
    subprocess.run(
        ["shadow", "-d", str(out_dir / "shadow.data"), "--progress", "true",
         str(out_dir / "shadow.yaml")],
        cwd=out_dir, check=True,
    )


def docker_run_shadow(image: str, out_dir: Path) -> None:
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], check=False, capture_output=True)
    log("running Shadow in container...")
    subprocess.run(
        ["docker", "run", "--rm", "--name", CONTAINER_NAME,
         "--platform", "linux/arm64",
         "--security-opt", "seccomp=unconfined",
         "--shm-size", "4g",
         "-v", f"{out_dir}:{out_dir}",
         "-w", str(out_dir),
         "--entrypoint", "/bin/bash", image,
         "-c", f"shadow -d {out_dir / 'shadow.data'} --progress true {out_dir / 'shadow.yaml'}"],
        check=True,
    )


_ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")


def summarize(out_dir: Path) -> None:
    hosts_dir = out_dir / "shadow.data" / "hosts"
    if not hosts_dir.is_dir():
        log(f"no shadow.data/hosts under {out_dir} — nothing to summarize.")
        return
    counts = {"hosts": 0, "published": 0, "l2": 0, "inputs": 0, "node_agg": 0,
              "root": 0, "aggregated": 0}
    for host in sorted(hosts_dir.iterdir()):
        stdout = host / STDOUT_NAME
        if not stdout.is_file():
            continue
        counts["hosts"] += 1
        text = _ANSI.sub("", stdout.read_text(errors="replace"))
        if "EVENT kind=proof_published" in text:
            counts["published"] += 1
        if host.name.startswith("l2-"):
            counts["l2"] += 1
            counts["inputs"] += "EVENT kind=inputs_complete" in text
            counts["node_agg"] += "EVENT kind=node_aggregate_complete" in text
            counts["root"] += bool(re.search(r"EVENT kind=tree_assigned .*root=true", text))
            counts["aggregated"] += "EVENT kind=aggregate_complete" in text
    log("── run summary ─────────────────────────────────────────────")
    log(f"hosts: {counts['hosts']}  L1 published: {counts['published']}")
    log(f"L2 inputs complete: {counts['inputs']}/{counts['l2']}  "
        f"node aggregate done: {counts['node_agg']}/{counts['l2']}")
    log(f"root aggregators with the global proof: {counts['aggregated']}/{counts['root']}")
    log("────────────────────────────────────────────────────────────")


def analyze_and_serve(out_dir: Path, overlays: list[Path], serve: bool,
                      append: bool = False) -> None:
    script = REPO_ROOT / "scripts" / "analyze.py"
    cmd = [sys.executable, str(script)]
    if serve:
        cmd.append("--serve")
    if append:
        cmd.append("--append")
    cmd += [str(d) for d in (out_dir, *overlays)]
    log("writing CLI summary + summary.html…")
    subprocess.run(cmd, cwd=str(REPO_ROOT), check=False)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run proof-broadcast-tree under Shadow.")
    ap.add_argument("config", nargs="?", default="proofsim.toml",
                    help="path to the TOML config (default: proofsim.toml)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build, then generate shadow.yaml + topology.gml only; no run")
    ap.add_argument("--rebuild", action="store_true", help="force `docker build` first")
    ap.add_argument("--clean", action="store_true",
                    help="remove previous shadow.data/, runs-history.json and summary.html")
    ap.add_argument("--summary-only", action="store_true",
                    help="skip generation/build/run; just summarize an existing run")
    ap.add_argument("--serve", "-s", action="store_true",
                    help="after the run, serve summary.html at http://0.0.0.0:4321")
    ap.add_argument("--serve-only", action="store_true",
                    help="skip the simulation; rebuild HTML from history and serve")
    ap.add_argument("--overlay", action="append", default=[], metavar="DIR",
                    help="extra output dir to import into the run history (repeatable)")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = REPO_ROOT / cfg_path
    if not cfg_path.is_file():
        die(f"config not found: {cfg_path}")
    with cfg_path.open("rb") as f:
        cfg = tomllib.load(f)
    sim = cfg.setdefault("sim", {})
    sim.setdefault("seed", 42)
    p = prover_settings(sim)
    topology_settings(cfg.get("topology", {}))
    nodes_in_tree = tree_size(p["subnets"], p["aggregation_arity"])
    if p["l2_provers"] < nodes_in_tree:
        die(f"l2_provers ({p['l2_provers']}) < tree nodes ({nodes_in_tree}): some tree "
            "node would certainly have no aggregator")

    out_dir = Path(cfg.get("output", {}).get("dir", "shadow-output"))
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir
    overlays = [p if p.is_absolute() else REPO_ROOT / p for p in map(Path, args.overlay)]

    if args.summary_only:
        summarize(out_dir)
        return
    if args.serve_only:
        analyze_and_serve(out_dir, overlays, serve=True)
        return

    runner = str(cfg.get("run", {}).get("runner", "docker")).lower()
    if runner not in ("docker", "native"):
        die(f'[run].runner must be "docker" or "native", got "{runner}"')
    bin_path = BIN_DOCKER if runner == "docker" else BIN_NATIVE
    docker_cfg = cfg.get("docker", {})
    image = docker_cfg.get("image_name", DEFAULT_IMAGE) if runner == "docker" else None

    out_dir.mkdir(parents=True, exist_ok=True)
    if args.clean:
        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        for name in ("runs-history.json", "summary.html"):
            (out_dir / name).unlink(missing_ok=True)
        log(f"cleaned {out_dir}")

    # The tree and every PeerId come from the binary, so even a dry run builds.
    if runner == "docker":
        shadow_image = docker_cfg.get("shadow_image", "kamilsa/shadow-arm:tcpfix")
        if args.rebuild or docker_cfg.get("rebuild") or not image_exists(image):
            docker_build(image, shadow_image)
        else:
            log(f"reusing existing image {image} (pass --rebuild to force a rebuild)")
    else:
        cargo_build_release()

    base_seed = int(sim["seed"])
    runs = max(1, int(sim.get("runs", 1)))
    for run_index in range(runs):
        run_seed = base_seed + run_index
        if runs > 1:
            log(f"─── run {run_index + 1}/{runs}  (seed {run_seed}) ───")
        nodes, tree = generate_run(cfg, out_dir, run_seed, bin_path, image)
        log(f"  runner: {runner}  arity: {p['aggregation_arity']}  fanout: {p['fanout']}")
        if args.dry_run:
            log("dry run — generated shadow.yaml only, skipping Shadow.")
            continue

        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        if runner == "docker":
            docker_run_shadow(image, out_dir)
        else:
            native_run_shadow(out_dir)

        (out_dir / "run-meta.json").write_text(json.dumps({
            "seed": run_seed, "run_index": run_index, "runs": runs,
            "title": str(sim.get("title") or ""),
            **prover_settings(sim),
            **topology_settings(cfg.get("topology", {})),
            **tree_meta(nodes, tree),
        }, indent=2))
        summarize(out_dir)
        # The next run overwrites shadow.data/, so record this one now.
        analyze_and_serve(out_dir, overlays, serve=False, append=True)

    if args.dry_run:
        return
    log(f"done. Results under: {out_dir}/shadow.data/hosts/<host>/{STDOUT_NAME}")
    if args.serve:
        analyze_and_serve(out_dir, overlays, serve=True, append=False)


if __name__ == "__main__":
    main()
