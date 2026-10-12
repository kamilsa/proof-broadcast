#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Launch a proof-broadcast network simulation under Shadow.

Reads a TOML config (default `proofsim.toml`), assigns prover roles
(`subnets x provers_per_subnet` L1 provers, then `l2_provers` L2 provers),
generates a geo-realistic Shadow topology (`topology.gml`) and a `shadow.yaml`
wiring every node's QUIC peers, then runs the simulation either:
  - in Docker  ([run].runner = "docker"): builds an image with proof-broadcast
    on top of a Shadow base image and runs Shadow in a container; or
  - natively   ([run].runner = "native"): builds with `cargo build --release`
    and runs a `shadow` binary from PATH.

Usage:
  uv run shadow-sim.py                      # build (if needed) + run with proofsim.toml
  uv run shadow-sim.py my.toml              # use a different config file
  uv run shadow-sim.py --dry-run            # generate shadow.yaml/topology.gml only
  uv run shadow-sim.py --rebuild            # force `docker build` first
  uv run shadow-sim.py --clean              # wipe shadow.data/, history and summary.html
  uv run shadow-sim.py --serve              # run, then serve the interactive summary
  uv run shadow-sim.py --netviz-trace       # also export a NetVis trace per run

Results land in `<output.dir>/shadow.data/hosts/<host>/proof-broadcast.1000.stdout`.
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

BIN_NAME = "proof-broadcast"
BIN_DOCKER = f"/opt/proofsim/{BIN_NAME}"
BIN_NATIVE = str(REPO_ROOT / "target" / "release" / BIN_NAME)
STDOUT_NAME = f"{BIN_NAME}.1000.stdout"

MODES = {"gossipsub", "partial"}
DEFAULT_MODE = "gossipsub"
# Keep in sync with the clap defaults in src/node.rs.
DEFAULT_SUBNETS = 16
DEFAULT_PROVERS_PER_SUBNET = 4
DEFAULT_L2_PROVERS = 64
DEFAULT_PROOF_SIZE_KIB = 300
DEFAULT_CHUNK_COUNT = 64
MAX_CHUNKS = 4096  # proof::MAX_CHUNKS
MAX_SUBNETS = 64  # proof::MAX_SUBNETS (committees fit a u64 mask)
DEFAULT_PROOF_JITTER_MS = 500
DEFAULT_PUBLISH_GRACE_SECS = 10
DEFAULT_AGGREGATION_MS = 290  # leanVM README: 2->1 recursion 0.287 s (M4 Max)
DEFAULT_AGGREGATION_WORKERS = 1
DEFAULT_INTERMEDIATE_PROOFS = False
DEFAULT_INTERMEDIATE_MIN_COMMITTEES = 2
FETCH_POLICIES = {"disjoint", "subsume"}
DEFAULT_INTERMEDIATE_FETCH = "disjoint"
DEFAULT_WARMUP_SECS = 15
DEFAULT_OBSERVE_SECS = 20
DEFAULT_FLOOD_PUBLISH = False
DEFAULT_GOSSIP_LAZY = 0
DEFAULT_GOSSIP_FACTOR = 0.0
DEFAULT_MESH = (8, 6, 12, 3)  # n, n_low, n_high, outbound_min
DEFAULT_L1_PEERS_PER_NODE = 16
DEFAULT_L2_PEERS_PER_NODE = 32
DEFAULT_BANDWIDTH_UP = "25 Mbit"    # EIP-7870
DEFAULT_BANDWIDTH_DOWN = "50 Mbit"

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

def _positive_int(sim: dict, key: str, default: int) -> int:
    value = int(sim.get(key, default))
    if value < 1:
        die(f"[sim].{key} must be >= 1, got {value}")
    return value


def _nonneg_int(sim: dict, key: str, default: int) -> int:
    value = int(sim.get(key, default))
    if value < 0:
        die(f"[sim].{key} must be >= 0, got {value}")
    return value


def mode_setting(sim: dict) -> str:
    mode = str(sim.get("mode", DEFAULT_MODE))
    if mode not in MODES:
        die(f"[sim].mode must be one of {sorted(MODES)}, got {mode!r}")
    return mode


def chunk_count_setting(sim: dict) -> int:
    count = _positive_int(sim, "chunk_count", DEFAULT_CHUNK_COUNT)
    if count > MAX_CHUNKS:
        die(f"[sim].chunk_count must be <= {MAX_CHUNKS}, got {count}")
    return count


def mesh_settings(sim: dict) -> tuple[int, int, int, int]:
    d_n, d_low, d_high, d_out = DEFAULT_MESH
    n = int(sim.get("proofs_mesh_n", d_n))
    low = int(sim.get("proofs_mesh_n_low", d_low))
    high = int(sim.get("proofs_mesh_n_high", d_high))
    out = int(sim.get("proofs_mesh_outbound_min", d_out))
    if not (0 <= out <= low <= n <= high):
        die("proofs mesh must satisfy 0 <= outbound_min <= n_low <= n <= n_high, "
            f"got {out} <= {low} <= {n} <= {high}")
    if 2 * out > n:
        die(f"proofs mesh must satisfy 2 * outbound_min <= n, got 2 * {out} > {n}")
    return n, low, high, out


def gossip_tuning_settings(sim: dict) -> tuple[bool, int, float]:
    flood = bool(sim.get("flood_publish", DEFAULT_FLOOD_PUBLISH))
    lazy = _nonneg_int(sim, "gossip_lazy", DEFAULT_GOSSIP_LAZY)
    factor = float(sim.get("gossip_factor", DEFAULT_GOSSIP_FACTOR))
    if not 0.0 <= factor <= 1.0:
        die(f"[sim].gossip_factor must be between 0 and 1, got {factor}")
    return flood, lazy, factor


def prover_settings(sim: dict) -> dict:
    """Validated prover / proof / aggregation parameters, as run metadata."""
    subnets = _positive_int(sim, "subnets", DEFAULT_SUBNETS)
    if subnets > MAX_SUBNETS:
        die(f"[sim].subnets must be <= {MAX_SUBNETS}, got {subnets}")
    return {
        "subnets": subnets,
        "provers_per_subnet": _positive_int(sim, "provers_per_subnet", DEFAULT_PROVERS_PER_SUBNET),
        "l2_provers": _positive_int(sim, "l2_provers", DEFAULT_L2_PROVERS),
        "proof_size_kib": _positive_int(sim, "proof_size_kib", DEFAULT_PROOF_SIZE_KIB),
        "chunk_count": chunk_count_setting(sim),
        "proof_jitter_ms": _nonneg_int(sim, "proof_jitter_ms", DEFAULT_PROOF_JITTER_MS),
        "publish_grace_secs": _nonneg_int(sim, "publish_grace_secs", DEFAULT_PUBLISH_GRACE_SECS),
        "aggregation_ms": _nonneg_int(sim, "aggregation_ms", DEFAULT_AGGREGATION_MS),
        "aggregation_workers": _positive_int(sim, "aggregation_workers",
                                             DEFAULT_AGGREGATION_WORKERS),
        **intermediate_settings(sim),
        "warmup_secs": _nonneg_int(sim, "warmup_secs", DEFAULT_WARMUP_SECS),
        "observe_secs": _nonneg_int(sim, "observe_secs", DEFAULT_OBSERVE_SECS),
    }


def intermediate_settings(sim: dict) -> dict:
    """L2s publishing their intermediate aggregates (never the final one)."""
    enabled = bool(sim.get("intermediate_proofs", DEFAULT_INTERMEDIATE_PROOFS))
    min_committees = int(sim.get("intermediate_min_committees",
                                 DEFAULT_INTERMEDIATE_MIN_COMMITTEES))
    if min_committees < 2:
        die(f"[sim].intermediate_min_committees must be >= 2, got {min_committees}")
    fetch = str(sim.get("intermediate_fetch", DEFAULT_INTERMEDIATE_FETCH))
    if fetch not in FETCH_POLICIES:
        die(f"[sim].intermediate_fetch must be one of {sorted(FETCH_POLICIES)}, got {fetch!r}")
    return {"intermediate_proofs": enabled, "intermediate_min_committees": min_committees,
            "intermediate_fetch": fetch}


def warn_unpublishable(p: dict) -> None:
    """Only aggregates covering min..subnets-1 committees are ever published."""
    if p["intermediate_proofs"] and p["intermediate_min_committees"] >= p["subnets"]:
        log(f"warning: intermediate_proofs is on but no aggregate can be published "
            f"(intermediate_min_committees={p['intermediate_min_committees']} >= "
            f"subnets={p['subnets']}; the final aggregate is never published)")


def role_bandwidth(net: dict, role: str) -> tuple[str, str]:
    section = net.get(role, {})
    return (str(section.get("bandwidth_up", DEFAULT_BANDWIDTH_UP)),
            str(section.get("bandwidth_down", DEFAULT_BANDWIDTH_DOWN)))


# ── nodes and topology ───────────────────────────────────────────────────────

class Node:
    """One simulated host: a Shadow host + a proof-broadcast process."""

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
        # An L2's prover index labels the intermediate aggregates it publishes.
        nodes.append(Node(l1 + j, f"l2-{j:0{width}d}", "l2", prover=j))
    base = ipaddress.ip_address("11.0.0.1")
    for node in nodes:
        node.ip = str(base + node.index)
    return nodes


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


def wire_peers(nodes: list[Node], l1_peers: int, l2_peers: int,
               rng: random.Random) -> dict[int, list[str]]:
    """L1 provers never subscribe, so an L1<->L1 link would carry nothing:
    every node dials only L2 provers."""
    l2 = [p for p in nodes if p.role == "l2"]
    out: dict[int, list[str]] = {}
    for node in nodes:
        count = l1_peers if node.role == "l1" else l2_peers
        candidates = [p for p in l2 if p.index != node.index]
        chosen = rng.sample(candidates, min(count, len(candidates)))
        out[node.index] = [f"/ip4/{p.ip}/udp/{CL_PORT}/quic-v1" for p in chosen]
    return out


def dump_peer_ids(seeds: list[int], bin_path: str, image: str | None) -> list[str] | None:
    if not seeds:
        return []
    seed_arg = ",".join(str(s) for s in seeds)
    if bin_path == BIN_DOCKER:
        if not image or not image_exists(image):
            return None
        cmd = ["docker", "run", "--rm", "--platform", "linux/arm64",
               "--entrypoint", BIN_DOCKER, image, "--dump-peer-ids", seed_arg]
    else:
        if not Path(bin_path).is_file():
            return None
        cmd = [bin_path, "--dump-peer-ids", seed_arg]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        die(f"--dump-peer-ids failed: {err}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def write_peers_json(nodes: list[Node], seed: int, out_dir: Path, bin_path: str,
                     image: str | None) -> None:
    """PeerId -> host map, so the analyzer can resolve `from=<peer>` fields."""
    peer_ids = dump_peer_ids([seed + node.index for node in nodes], bin_path, image)
    if peer_ids is None:
        log("skipping peers.json (binary/image not available)")
        return
    if len(peer_ids) != len(nodes):
        die(f"--dump-peer-ids returned {len(peer_ids)} ids, expected {len(nodes)}")
    peers = [{"name": node.name, "peer_id": pid, "role": node.role,
              "addr": f"/ip4/{node.ip}/udp/{CL_PORT}/quic-v1"}
             for node, pid in zip(nodes, peer_ids)]
    (out_dir / "peers.json").write_text(json.dumps({"peers": peers}, indent=2) + "\n")


def build_args(node: Node, cfg: dict, peers: list[str]) -> str:
    sim = cfg["sim"]
    p = prover_settings(sim)
    parts: list[str] = [
        "--mode", mode_setting(sim),
        "--role", node.role,
        "--seed", str(int(sim["seed"]) + node.index),
        "--listen-port", str(CL_PORT),
        "--subnets", str(p["subnets"]),
        "--proof-size-kib", str(p["proof_size_kib"]),
        "--chunk-count", str(p["chunk_count"]),
        "--aggregation-ms", str(p["aggregation_ms"]),
        "--aggregation-workers", str(p["aggregation_workers"]),
        "--warmup-secs", str(p["warmup_secs"]),
        "--observe-secs", str(p["observe_secs"]),
        "--publish-grace-secs", str(p["publish_grace_secs"]),
    ]
    if node.role == "l1":
        parts += ["--subnet", str(node.subnet), "--prover", str(node.prover),
                  "--publish-delay-ms", str(node.publish_delay_ms)]
    else:
        parts += ["--prover", str(node.prover)]
        if p["intermediate_proofs"]:
            parts += ["--intermediate-proofs",
                      "--intermediate-min-committees", str(p["intermediate_min_committees"]),
                      "--intermediate-fetch", p["intermediate_fetch"]]
    flood, lazy, factor = gossip_tuning_settings(sim)
    if flood:
        parts.append("--flood-publish")
    parts += ["--gossip-lazy", str(lazy), "--gossip-factor", str(factor)]
    n, low, high, out = mesh_settings(sim)
    parts += ["--proofs-mesh-n", str(n), "--proofs-mesh-n-low", str(low),
              "--proofs-mesh-n-high", str(high), "--proofs-mesh-outbound-min", str(out)]
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
                 image: str | None = None) -> list[Node]:
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
        node.bandwidth_up, node.bandwidth_down = role_bandwidth(net, node.role)

    gml_path = out_dir / "topology.gml"
    gml_path.write_text(generate_gml(nodes, jitter_ratio, packet_loss, geo_rng))
    (out_dir / "nodes.json").write_text(json.dumps({
        node.name: {"role": node.role, "subnet": node.subnet if node.role == "l1" else None,
                    "prover": node.prover,
                    "publish_delay_ms": node.publish_delay_ms if node.role == "l1" else None,
                    "region": node.region,
                    "up": node.bandwidth_up, "down": node.bandwidth_down}
        for node in nodes
    }, indent=2))
    write_peers_json(nodes, seed, out_dir, bin_path, image)

    peers = wire_peers(
        nodes,
        int(topo.get("l1_peers_per_node", DEFAULT_L1_PEERS_PER_NODE)),
        int(topo.get("l2_peers_per_node", DEFAULT_L2_PEERS_PER_NODE)),
        random.Random(seed + 1),
    )
    (out_dir / "shadow.yaml").write_text(
        generate_shadow_yaml(nodes, cfg, gml_path, peers, bin_path))

    l1 = sum(1 for x in nodes if x.role == "l1")
    log(f"  {len(nodes)} hosts: {l1} L1 provers, {len(nodes) - l1} L2 provers")
    return nodes


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
    log("building proof-broadcast (cargo build --release)...")
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
    subprocess.run(["docker", "rm", "-f", "proofsim-shadow-run"],
                   check=False, capture_output=True)
    log("running Shadow in container...")
    subprocess.run(
        ["docker", "run", "--rm", "--name", "proofsim-shadow-run",
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
    counts = {"hosts": 0, "published": 0, "l2": 0, "all_subnets": 0, "aggregated": 0,
              "intermediates": 0, "fetched": 0}
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
            counts["all_subnets"] += "EVENT kind=all_subnets_complete" in text
            counts["aggregated"] += "EVENT kind=aggregate_complete" in text
            counts["intermediates"] += text.count("EVENT kind=intermediate_published")
            counts["fetched"] += text.count("EVENT kind=intermediate_complete")
    log("── run summary ─────────────────────────────────────────────")
    log(f"hosts: {counts['hosts']}  L1 published: {counts['published']}")
    log(f"L2 collected all subnets: {counts['all_subnets']}/{counts['l2']}  "
        f"aggregated: {counts['aggregated']}/{counts['l2']}")
    if counts["intermediates"]:
        log(f"intermediate aggregates published: {counts['intermediates']}  "
            f"fetched: {counts['fetched']}")
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
    ap = argparse.ArgumentParser(description="Run proof-broadcast under Shadow.")
    ap.add_argument("config", nargs="?", default="proofsim.toml",
                    help="path to the TOML config (default: proofsim.toml)")
    ap.add_argument("--dry-run", action="store_true",
                    help="generate shadow.yaml + topology.gml only; no build or run")
    ap.add_argument("--rebuild", action="store_true", help="force `docker build` first")
    ap.add_argument("--netviz-trace", action="store_true",
                    help="export a NetVis trace (proof-broadcast decoder) after each run")
    ap.add_argument("--clean", action="store_true",
                    help="remove previous shadow.data/, runs-history.json, summary.html "
                         "and NetVis traces")
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
    mode_setting(sim)
    warn_unpublishable(prover_settings(sim))
    mesh_settings(sim)
    gossip_tuning_settings(sim)

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
    image = docker_cfg.get("image_name", "proofsim-shadow:local") if runner == "docker" else None

    out_dir.mkdir(parents=True, exist_ok=True)
    if args.clean:
        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        for name in ("runs-history.json", "summary.html"):
            (out_dir / name).unlink(missing_ok=True)
        for trace in out_dir.glob("proof-broadcast*.netviz.ndjson"):
            trace.unlink()
        log(f"cleaned {out_dir}")

    if not args.dry_run:
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
        generate_run(cfg, out_dir, run_seed, bin_path, image)
        log(f"  runner: {runner}  mode: {mode_setting(sim)}")
        if args.dry_run:
            log("dry run — generated shadow.yaml only, skipping Shadow.")
            continue

        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        if runner == "docker":
            docker_run_shadow(image, out_dir)
        else:
            native_run_shadow(out_dir)

        flood, lazy, factor = gossip_tuning_settings(sim)
        n, low, high, out = mesh_settings(sim)
        (out_dir / "run-meta.json").write_text(json.dumps({
            "seed": run_seed, "run_index": run_index, "runs": runs,
            "title": str(sim.get("title") or ""),
            "mode": mode_setting(sim),
            **prover_settings(sim),
            "flood_publish": flood, "gossip_lazy": lazy, "gossip_factor": factor,
            "proofs_mesh_n": n, "proofs_mesh_n_low": low,
            "proofs_mesh_n_high": high, "proofs_mesh_outbound_min": out,
        }, indent=2))
        if args.netviz_trace:
            # The next run overwrites shadow.data/, so export each trace now.
            trace = out_dir / (f"proof-broadcast-{run_index}.netviz.ndjson" if runs > 1
                               else "proof-broadcast.netviz.ndjson")
            subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "export_netviz.py"),
                            str(out_dir), str(trace)], check=True)
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
