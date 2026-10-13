import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


shadow_sim = load("shadow_sim", ROOT / "shadow-sim.py")
analyze = load("analyze", ROOT / "scripts" / "analyze.py")


def small_cfg(**sim) -> dict:
    base = {"seed": 7, "subnets": 4, "provers_per_subnet": 2, "l2_provers": 8,
            "proof_jitter_ms": 300}
    base.update(sim)
    return {"sim": base,
            "topology": {"l1_peers_per_node": 2, "tree_mates_per_node": 1,
                         "tree_parent_peers": 2},
            "network": {"regions": {"europe": 1.0, "asia": 1.0},
                        "l1": {"bandwidth_up": "10 Mbit", "bandwidth_down": "20 Mbit"}}}


TREE_4_2 = [  # what `--dump-tree --subnets 4 --aggregation-arity 2` prints
    {"id": 0, "level": 0, "mask": 3, "committees": [0, 1], "parent": 2,
     "child_nodes": [], "input_subnets": [0, 1]},
    {"id": 1, "level": 0, "mask": 12, "committees": [2, 3], "parent": 2,
     "child_nodes": [], "input_subnets": [2, 3]},
    {"id": 2, "level": 1, "mask": 15, "committees": [0, 1, 2, 3], "parent": None,
     "child_nodes": [0, 1], "input_subnets": []},
]


def fake_tree(nodes, positions=None) -> dict:
    """A `--dump-tree` document for TREE_4_2; L2 j sits at positions[j]
    (default: round robin over the three tree nodes)."""
    l2 = [n for n in nodes if n.role == "l2"]
    positions = positions or [j % 3 for j in range(len(l2))]
    pos = {n.index: positions[j] for j, n in enumerate(l2)}
    return {"subnets": 4, "arity": 2, "depth": 2, "nodes": TREE_4_2,
            "peers": [{"seed": 7 + n.index, "peer_id": f"12D3Koo{n.index:04d}",
                       "tree_node": pos.get(n.index, 0)} for n in nodes]}


def placed_nodes(cfg=None, positions=None):
    nodes = shadow_sim.build_nodes((cfg or small_cfg())["sim"])
    tree = fake_tree(nodes, positions)
    shadow_sim.apply_tree(nodes, tree)
    return nodes, tree


class RoleAssignmentTests(unittest.TestCase):
    def test_l1_provers_cover_every_subnet_then_l2(self) -> None:
        nodes = shadow_sim.build_nodes(small_cfg()["sim"])
        l1 = [n for n in nodes if n.role == "l1"]
        l2 = [n for n in nodes if n.role == "l2"]
        self.assertEqual(len(l1), 8)
        self.assertEqual(len(l2), 8)
        self.assertEqual(sorted({n.subnet for n in l1}), [0, 1, 2, 3])
        self.assertEqual([n.prover for n in l2], list(range(8)))
        self.assertEqual(len({n.ip for n in nodes}), len(nodes))

    def test_l2_supernodes_are_an_exact_seeded_fraction(self) -> None:
        net = small_cfg()["network"]
        net["l2_supernodes"] = {"fraction": 0.5, "bandwidth_up": "1 Gbit",
                                "bandwidth_down": "1 Gbit"}

        def pick() -> list[str]:
            nodes = shadow_sim.build_nodes(small_cfg()["sim"])
            shadow_sim.assign_bandwidth(nodes, net, 7)
            return [n.name for n in nodes if n.supernode]

        chosen = pick()
        self.assertEqual(len(chosen), 4)
        self.assertTrue(all(name.startswith("l2-") for name in chosen))
        self.assertEqual(chosen, pick())

    def test_l1_supernodes_are_picked_independently_of_l2(self) -> None:
        net = small_cfg()["network"]
        net["l2_supernodes"] = {"fraction": 0.5, "bandwidth_up": "1 Gbit",
                                "bandwidth_down": "1 Gbit"}

        def pick(net) -> list[str]:
            nodes = shadow_sim.build_nodes(small_cfg()["sim"])
            shadow_sim.assign_bandwidth(nodes, net, 7)
            return [n for n in nodes if n.supernode]

        l2_only = [n.name for n in pick(net)]
        net["l1_supernodes"] = {"fraction": 0.25, "bandwidth_up": "500 Mbit",
                                "bandwidth_down": "1 Gbit"}
        both = pick(net)
        l1 = [n for n in both if n.role == "l1"]
        self.assertEqual(len(l1), 2)                   # a quarter of 8 L1s
        self.assertTrue(all((n.bandwidth_up, n.bandwidth_down) == ("500 Mbit", "1 Gbit")
                            for n in l1))
        # Adding L1 supernodes leaves the L2 pick unchanged.
        self.assertEqual([n.name for n in both if n.role == "l2"], l2_only)
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit):
            net["l1_supernodes"]["fraction"] = 2
            pick(net)

    def test_publish_delays_are_seeded_and_bounded(self) -> None:
        a = shadow_sim.build_nodes(small_cfg()["sim"])
        b = shadow_sim.build_nodes(small_cfg()["sim"])
        shadow_sim.assign_publish_delays(a, 300, 7)
        shadow_sim.assign_publish_delays(b, 300, 7)
        self.assertEqual([n.publish_delay_ms for n in a], [n.publish_delay_ms for n in b])
        self.assertTrue(all(0 <= n.publish_delay_ms <= 300 for n in a if n.role == "l1"))
        self.assertTrue(all(n.publish_delay_ms == 0 for n in a if n.role == "l2"))

    def test_tree_positions_come_from_the_dump(self) -> None:
        nodes, _ = placed_nodes()
        l2 = [n for n in nodes if n.role == "l2"]
        self.assertEqual([n.tree_node for n in l2], [0, 1, 2, 0, 1, 2, 0, 1])
        # An L1's tree node is the node consuming its subnet.
        self.assertEqual({n.subnet: n.tree_node for n in nodes if n.role == "l1"},
                         {0: 0, 1: 0, 2: 1, 3: 1})
        self.assertTrue(all(n.peer_id.startswith("12D3Koo") for n in nodes))


class SettingsTests(unittest.TestCase):
    def test_defaults(self) -> None:
        p = shadow_sim.prover_settings({})
        self.assertEqual(p["subnets"], 16)
        self.assertEqual(p["aggregation_arity"], 2)
        self.assertEqual(p["max_inflight_per_peer"], 64)
        self.assertEqual((p["fanout"], p["have_interval_ms"]), (8, 10))
        t = shadow_sim.topology_settings({})
        self.assertEqual((t["l1_peers_per_node"], t["tree_mates_per_node"],
                          t["tree_parent_peers"]), (4, 8, 4))

    def test_invalid_settings_are_rejected(self) -> None:
        for bad in ({"subnets": 1}, {"subnets": 65}, {"aggregation_arity": 1},
                    {"aggregation_arity": 65}, {"chunk_count": 5000},
                    {"max_inflight_per_peer": 0}, {"l2_provers": 0}, {"fanout": 0},
                    {"have_interval_ms": -1}):
            with self.subTest(bad=bad), redirect_stdout(StringIO()):
                with self.assertRaises(SystemExit):
                    shadow_sim.prover_settings(bad)
        with self.assertRaises(SystemExit):
            shadow_sim.topology_settings({"tree_parent_peers": 0})

    def test_tree_size_matches_the_rust_tree(self) -> None:
        # Mirrors the fixtures in src/tree.rs.
        self.assertEqual(shadow_sim.tree_size(16, 2), 15)
        self.assertEqual(shadow_sim.tree_size(16, 4), 5)
        self.assertEqual(shadow_sim.tree_size(5, 2), 4)
        self.assertEqual(shadow_sim.tree_size(10, 4), 4)
        self.assertEqual(shadow_sim.tree_size(4, 8), 1)
        self.assertEqual(shadow_sim.tree_size(64, 2), 63)
        self.assertEqual(shadow_sim.tree_size(64, 4), 21)


class WiringTests(unittest.TestCase):
    def test_peers_are_dialed_along_the_tree(self) -> None:
        cfg = small_cfg()
        nodes, tree = placed_nodes(cfg)
        import random
        peers = shadow_sim.wire_peers(nodes, tree, cfg["topology"], random.Random(1))
        by_addr = {f"/ip4/{n.ip}/udp/{shadow_sim.CL_PORT}/quic-v1": n for n in nodes}
        for node in nodes:
            dialed = [by_addr[a] for a in peers[node.index]]
            self.assertTrue(all(d.role == "l2" for d in dialed), node.name)
            if node.role == "l1":
                self.assertEqual(len(dialed), 2)
                self.assertTrue(all(d.tree_node == node.tree_node for d in dialed))
                continue
            mates = [d for d in dialed if d.tree_node == node.tree_node]
            self.assertLessEqual(len(mates), 1)
            self.assertNotIn(node, dialed)
            parent = TREE_4_2[node.tree_node]["parent"]
            ups = [d for d in dialed if d.tree_node != node.tree_node]
            if parent is None:
                self.assertEqual(ups, [], "the root has no parent to dial")
            else:
                self.assertEqual(len(ups), 2)
                self.assertTrue(all(d.tree_node == parent for d in ups))

    def test_empty_tree_nodes_are_reported(self) -> None:
        nodes, tree = placed_nodes(positions=[0, 0, 0, 2, 2, 2, 0, 2])
        self.assertEqual(shadow_sim.empty_tree_nodes(nodes, tree), [1])
        meta = shadow_sim.tree_meta(nodes, tree)
        self.assertEqual(meta["members_per_node"], [4, 0, 4])
        self.assertEqual(meta["nodes_per_level"], [2, 1])
        self.assertEqual(meta["tree_depth"], 2)


class ArgsTests(unittest.TestCase):
    def test_l1_args_carry_role_subnet_and_delay(self) -> None:
        cfg = small_cfg(aggregation_arity=4, fanout=3, have_interval_ms=0)
        node = shadow_sim.Node(3, "l1-s01-p1", "l1", subnet=1, prover=1)
        node.publish_delay_ms = 123
        args = shadow_sim.build_args(node, cfg, ["/ip4/1.2.3.4/udp/9000/quic-v1"]).split()
        pairs = dict(zip(args[::2], args[1::2]))
        self.assertEqual(pairs["--role"], "l1")
        self.assertEqual(pairs["--seed"], "10")          # seed + index
        self.assertEqual(pairs["--subnet"], "1")
        self.assertEqual(pairs["--publish-delay-ms"], "123")
        self.assertEqual(pairs["--aggregation-arity"], "4")
        self.assertEqual(pairs["--fanout"], "3")
        self.assertEqual(pairs["--have-interval-ms"], "0")
        self.assertEqual(pairs["--peer"], "/ip4/1.2.3.4/udp/9000/quic-v1")

    def test_l2_args_have_no_publish_fields(self) -> None:
        node = shadow_sim.Node(9, "l2-001", "l2", prover=1)
        args = shadow_sim.build_args(node, small_cfg(), [])
        self.assertIn("--role l2", args)
        self.assertIn("--prover 1", args)
        self.assertNotIn("--subnet ", args)
        self.assertNotIn("--publish-delay-ms", args)


class DryRunTests(unittest.TestCase):
    def test_generate_run_writes_topology_and_yaml(self) -> None:
        cfg = small_cfg()
        nodes = shadow_sim.build_nodes(cfg["sim"])
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            out = Path(tmp)
            got, tree = shadow_sim.generate_run(cfg, out, 7, "/nonexistent/bin",
                                                tree=fake_tree(nodes))
            yaml = (out / "shadow.yaml").read_text()
            meta = json.loads((out / "nodes.json").read_text())
            peers = json.loads((out / "peers.json").read_text())["peers"]
            tree_json = json.loads((out / "tree.json").read_text())
        self.assertEqual(len(got), 16)
        self.assertEqual(yaml.count("    processes:"), 16)
        self.assertIn('bandwidth_up: "10 Mbit"', yaml)   # L1 override
        self.assertIn('bandwidth_up: "25 Mbit"', yaml)   # L2 default
        self.assertEqual(meta["l1-s03-p1"]["subnet"], 3)
        self.assertEqual(meta["l1-s03-p1"]["tree_node"], 1)
        self.assertEqual(meta["l2-002"]["tree_node"], 2)
        self.assertEqual(meta["l2-002"]["level"], 1)
        self.assertEqual(meta["l2-002"]["committees"], [0, 1, 2, 3])
        self.assertEqual(len(peers), 16)
        self.assertEqual(tree_json, TREE_4_2)
        self.assertEqual(tree["depth"], 2)

    def test_generate_run_needs_the_binary_without_a_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            with self.assertRaises(SystemExit):
                shadow_sim.generate_run(small_cfg(), Path(tmp), 7, "/nonexistent/bin")


def write_host(root: Path, name: str, lines: list[str]) -> None:
    host = root / "shadow.data" / "hosts" / name
    host.mkdir(parents=True)
    (host / "proof-broadcast-tree.1000.stdout").write_text("\n".join(lines) + "\n")


class AnalyzeTests(unittest.TestCase):
    def write_run(self, root: Path) -> None:
        """4 subnets, arity 2: leaves l2-000 (node 0) and l2-001 (node 1),
        root l2-002 (node 2); two L1s per leaf."""
        (root / "run-meta.json").write_text(json.dumps({
            "title": "t", "seed": 1, "run_index": 0, "subnets": 4, "aggregation_arity": 2,
            "proof_size_kib": 1, "tree_nodes": 3, "tree_depth": 2, "empty_tree_nodes": [],
            "fanout": 8}))
        (root / "tree.json").write_text(json.dumps(TREE_4_2))
        for name, t, h in (("l1-s00-p0", 1000, "a0"), ("l1-s01-p0", 1100, "a1"),
                           ("l1-s02-p0", 1050, "b0"), ("l1-s03-p0", 1200, "b1")):
            write_host(root, name, [
                f"EVENT kind=proof_published t_ms={t} t_us=0 subnet=0 prover=0 hash={h}",
                "EVENT kind=bytes t_ms=9000 t_us=0 tx=2048 rx=100 tx_data=2000 rx_data=0",
                f"EVENT kind=proof_served t_ms=9000 t_us=0 hash={h} mask=1 peers=2 chunks=4",
                "EVENT kind=run_end t_ms=9000 t_us=0 role=l1 chunks_served=4 fanout_peak=2"])
        write_host(root, "l2-000", [
            "EVENT kind=tree_assigned t_ms=0 t_us=0 node=0 level=0 depth=2 root=false",
            "EVENT kind=proof_complete t_ms=1300 t_us=0 subnet=0 hash=a0",
            "EVENT kind=proof_complete t_ms=1400 t_us=0 subnet=1 hash=a1",
            "EVENT kind=inputs_complete t_ms=1400 t_us=0 node=0 inputs=2",
            "EVENT kind=node_aggregate_complete t_ms=1700 t_us=0 node=0 level=0 hash=c0",
            "EVENT kind=bytes t_ms=9000 t_us=0 tx=1000 rx=2100 tx_data=900 rx_data=2048",
            "EVENT kind=proof_served t_ms=9000 t_us=0 hash=a0 mask=1 peers=1 chunks=2",
            "EVENT kind=proof_served t_ms=9000 t_us=0 hash=c0 mask=3 peers=1 chunks=2",
            "EVENT kind=run_end t_ms=9000 t_us=0 role=l2 declined=1 chunk_failures=2 "
            "chunks_served=4 chunks_served_partial=1 chunks_refused=3 fanout_peak=1"])
        write_host(root, "l2-001", [
            "EVENT kind=tree_assigned t_ms=0 t_us=0 node=1 level=0 depth=2 root=false",
            "EVENT kind=proof_complete t_ms=1250 t_us=0 subnet=2 hash=b0",
            "EVENT kind=proof_complete t_ms=1500 t_us=0 subnet=3 hash=b1",
            "EVENT kind=inputs_complete t_ms=1500 t_us=0 node=1 inputs=2",
            "EVENT kind=node_aggregate_complete t_ms=1800 t_us=0 node=1 level=0 hash=c1",
            "EVENT kind=bytes t_ms=9000 t_us=0 tx=1000 rx=2300 tx_data=900 rx_data=2048",
            "EVENT kind=run_end t_ms=9000 t_us=0 role=l2 declined=3"])
        write_host(root, "l2-002", [
            "EVENT kind=tree_assigned t_ms=0 t_us=0 node=2 level=1 depth=2 root=true",
            "EVENT kind=intermediate_complete t_ms=1900 t_us=0 committees=0-1 hash=c0",
            "EVENT kind=intermediate_complete t_ms=1950 t_us=0 committees=2-3 hash=c1",
            "EVENT kind=inputs_complete t_ms=1950 t_us=0 node=2 inputs=2",
            "EVENT kind=node_aggregate_complete t_ms=2250 t_us=0 node=2 level=1 hash=r",
            "EVENT kind=aggregate_complete t_ms=2250 t_us=0 subnets=4 node=2",
            "EVENT kind=bytes t_ms=9000 t_us=0 tx=10 rx=2200 tx_data=0 rx_data=2048",
            "EVENT kind=run_end t_ms=9000 t_us=0 role=l2 declined=0"])

    def test_collect_run_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_run(root)
            run = analyze.collect_run(root)
        self.assertEqual(run["t0_ms"], 1000)
        self.assertEqual((run["n_l1"], run["n_l2"], run["l1_published"]), (4, 3, 4))
        self.assertEqual((run["n_root"], run["root_done"]), (1, 1))
        self.assertEqual(run["root_first_ms"], 1250)
        self.assertEqual(run["root_max_ms"], 1250)
        self.assertEqual(run["node_done"], 3)
        self.assertEqual(run["stalled_l2"], 0)
        lv0, lv1 = run["levels"]
        self.assertEqual((lv0["nodes"], lv0["members"], lv0["done"]), (2, 2, 2))
        self.assertEqual(lv0["first_ms"], 700)
        self.assertEqual(lv0["ready_ms"], 800)        # both leaves have an aggregate
        self.assertEqual(lv0["inputs_t50_ms"], 400)
        self.assertEqual(lv1["ready_ms"], 1250)
        # Hops: a0 300, a1 300, b0 200, b1 300, c0 200, c1 150.
        self.assertEqual(run["hop_latency_median_ms"], 250)
        self.assertEqual(run["l1_amplification"], 2.0)   # 2 KiB sent for a 1 KiB proof
        self.assertEqual(run["declined_median"], 1)
        self.assertEqual(run["chunk_failures_total"], 2)
        self.assertEqual(run["fanout"], 8)
        self.assertEqual(run["fanout_peak"], 2)
        self.assertEqual(run["peers_per_proof_median"], 2)     # [1, 1, 2, 2, 2, 2]
        self.assertEqual(run["peers_per_proof_max"], 2)
        self.assertEqual(run["chunks_refused_total"], 3)
        self.assertEqual(run["l2_relaying"], 1)
        self.assertEqual(run["cut_through_share"], 1 / 20)     # 1 of 16 + 4 served

    def test_unready_level_and_stalled_l2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_run(root)
            stdout = root / "shadow.data/hosts/l2-001/proof-broadcast-tree.1000.stdout"
            stdout.write_text("\n".join(
                line for line in stdout.read_text().splitlines()
                if "node_aggregate_complete" not in line) + "\n")
            run = analyze.collect_run(root)
        self.assertIsNone(run["levels"][0]["ready_ms"])
        self.assertEqual(run["stalled_l2"], 1)

    def test_parse_event_line(self) -> None:
        ev = analyze.parse_event_line(
            "\x1b[2m2026\x1b[0m INFO event: EVENT kind=x t_ms=5 t_us=1 a=1 b=true c=0-1 d=NA")
        self.assertEqual(ev, {"kind": "x", "t_ms": 5, "t_us": 1, "a": 1, "b": True,
                              "c": "0-1", "d": None})
        self.assertIsNone(analyze.parse_event_line("no event here"))

    def test_history_and_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            root = Path(tmp)
            self.write_run(root)
            history = analyze.update_history(root, [], append=True)
            analyze.write_html(history, root / analyze.HTML_NAME)
            html = (root / analyze.HTML_NAME).read_text()
        self.assertEqual(len(history), 1)
        self.assertIn("<title>Proof Tree Runs</title>", html)
        self.assertIn("1250 ms", html)


if __name__ == "__main__":
    unittest.main()
