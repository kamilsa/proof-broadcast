import importlib.util
import json
import sys
import tempfile
import unittest
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
export_netviz = load("export_netviz", ROOT / "scripts" / "export_netviz.py")


def small_cfg(**sim) -> dict:
    base = {"seed": 7, "mode": "partial", "subnets": 4, "provers_per_subnet": 2,
            "l2_provers": 8, "proof_jitter_ms": 300, "proofs_mesh_n": 4,
            "proofs_mesh_n_low": 3, "proofs_mesh_n_high": 6, "proofs_mesh_outbound_min": 1}
    base.update(sim)
    return {"sim": base, "topology": {"l1_peers_per_node": 4, "l2_peers_per_node": 5},
            "network": {"regions": {"europe": 1.0, "asia": 1.0},
                        "l1": {"bandwidth_up": "10 Mbit", "bandwidth_down": "20 Mbit"}}}


class RoleAssignmentTests(unittest.TestCase):
    def test_l1_provers_cover_every_subnet_then_l2(self) -> None:
        nodes = shadow_sim.build_nodes(small_cfg()["sim"])
        l1 = [n for n in nodes if n.role == "l1"]
        l2 = [n for n in nodes if n.role == "l2"]
        self.assertEqual(len(l1), 8)
        self.assertEqual(len(l2), 8)
        self.assertEqual([(n.subnet, n.prover) for n in l1],
                         [(s, p) for s in range(4) for p in range(2)])
        self.assertEqual(nodes[:8], l1)
        self.assertEqual(len({n.ip for n in nodes}), len(nodes))
        self.assertEqual(len({n.name for n in nodes}), len(nodes))

    def test_publish_delays_are_seeded_and_bounded(self) -> None:
        a = shadow_sim.build_nodes(small_cfg()["sim"])
        b = shadow_sim.build_nodes(small_cfg()["sim"])
        shadow_sim.assign_publish_delays(a, 300, 7)
        shadow_sim.assign_publish_delays(b, 300, 7)
        self.assertEqual([n.publish_delay_ms for n in a], [n.publish_delay_ms for n in b])
        for n in a:
            if n.role == "l1":
                self.assertTrue(0 <= n.publish_delay_ms <= 300)
            else:
                self.assertEqual(n.publish_delay_ms, 0)

    def test_zero_jitter_publishes_together(self) -> None:
        nodes = shadow_sim.build_nodes(small_cfg()["sim"])
        shadow_sim.assign_publish_delays(nodes, 0, 7)
        self.assertTrue(all(n.publish_delay_ms == 0 for n in nodes))


class WiringTests(unittest.TestCase):
    def test_everyone_dials_only_l2_provers(self) -> None:
        import random
        nodes = shadow_sim.build_nodes(small_cfg()["sim"])
        peers = shadow_sim.wire_peers(nodes, 4, 5, random.Random(1))
        l2_addrs = {f"/ip4/{n.ip}/udp/{shadow_sim.CL_PORT}/quic-v1"
                    for n in nodes if n.role == "l2"}
        for node in nodes:
            dialed = peers[node.index]
            self.assertTrue(set(dialed) <= l2_addrs)
            self.assertEqual(len(dialed), 4 if node.role == "l1" else 5)
            self.assertNotIn(f"/ip4/{node.ip}/udp/{shadow_sim.CL_PORT}/quic-v1", dialed)


class ArgsTests(unittest.TestCase):
    def test_l1_args_carry_role_subnet_and_delay(self) -> None:
        cfg = small_cfg()
        node = shadow_sim.Node(3, "l1-s01-p1", "l1", subnet=1, prover=1)
        node.publish_delay_ms = 123
        args = shadow_sim.build_args(node, cfg, ["/ip4/1.2.3.4/udp/9000/quic-v1"]).split()
        pairs = dict(zip(args[::2], args[1::2]))
        self.assertEqual(pairs["--role"], "l1")
        self.assertEqual(pairs["--subnet"], "1")
        self.assertEqual(pairs["--prover"], "1")
        self.assertEqual(pairs["--publish-delay-ms"], "123")
        self.assertEqual(pairs["--seed"], "10")
        self.assertEqual(pairs["--mode"], "partial")
        self.assertEqual(pairs["--aggregation-ms"], "290")
        self.assertEqual(pairs["--peer"], "/ip4/1.2.3.4/udp/9000/quic-v1")

    def test_l2_args_have_no_publish_fields(self) -> None:
        args = shadow_sim.build_args(shadow_sim.Node(9, "l2-000", "l2"), small_cfg(), [])
        self.assertIn("--role l2", args)
        self.assertNotIn("--subnet ", args)
        self.assertNotIn("--publish-delay-ms", args)

    def test_invalid_settings_are_rejected(self) -> None:
        for bad in ({"mode": "flood"}, {"chunk_count": 0}, {"chunk_count": 5000},
                    {"proofs_mesh_n": 2}, {"subnets": 0}):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                cfg = small_cfg(**bad)
                shadow_sim.mode_setting(cfg["sim"])
                shadow_sim.prover_settings(cfg["sim"])
                shadow_sim.mesh_settings(cfg["sim"])


class DryRunTests(unittest.TestCase):
    def test_generate_run_writes_topology_and_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            nodes = shadow_sim.generate_run(small_cfg(), out, 7, "/nonexistent/bin")
            yaml = (out / "shadow.yaml").read_text()
            gml = (out / "topology.gml").read_text()
            meta = json.loads((out / "nodes.json").read_text())
            self.assertEqual(len(nodes), 16)
            self.assertEqual(yaml.count("    processes:"), 16)
            self.assertIn('bandwidth_up: "10 Mbit"', yaml)   # L1 override
            self.assertIn('bandwidth_up: "25 Mbit"', yaml)   # L2 default
            self.assertEqual(gml.count("  node ["), 16)
            self.assertEqual(meta["l1-s03-p1"]["subnet"], 3)
            self.assertIsNone(meta["l2-000"]["subnet"])


def write_host(root: Path, name: str, lines: list[str]) -> None:
    host = root / "shadow.data" / "hosts" / name
    host.mkdir(parents=True)
    (host / "proof-broadcast.1000.stdout").write_text("\n".join(lines) + "\n")


class AnalyzeTests(unittest.TestCase):
    def test_collect_run_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "run-meta.json").write_text(json.dumps(
                {"mode": "partial", "seed": 1, "run_index": 0, "subnets": 2,
                 "proof_size_kib": 1}))
            write_host(root, "l1-s00-p0", [
                "INFO EVENT kind=proof_published t_ms=1000 subnet=0 prover=0 hash=aa",
                "INFO EVENT kind=bytes t_ms=9000 tx=4096 rx=10"])
            write_host(root, "l1-s01-p0", [
                "INFO EVENT kind=proof_published t_ms=1100 subnet=1 prover=0 hash=bb",
                "INFO EVENT kind=bytes t_ms=9000 tx=2048 rx=10"])
            write_host(root, "l2-000", [
                "EVENT kind=proof_complete t_ms=1300 subnet=0 prover=0 hash=aa",
                "EVENT kind=proof_complete t_ms=1500 subnet=1 prover=0 hash=bb",
                "EVENT kind=all_subnets_complete t_ms=1500 subnets=2",
                "EVENT kind=aggregate_complete t_ms=1790 subnets=2",
                "EVENT kind=bytes t_ms=9000 tx=100 rx=4096",
                "EVENT kind=run_end t_ms=9000 role=l2 subnets_done=2 aggregated=true "
                "redundant_proofs=0 duplicate_chunks=3 declined=1"])
            write_host(root, "l2-001", [
                "EVENT kind=proof_complete t_ms=1400 subnet=0 prover=0 hash=aa",
                "EVENT kind=bytes t_ms=9000 tx=100 rx=1024",
                "EVENT kind=run_end t_ms=9000 role=l2 subnets_done=1 aggregated=false "
                "redundant_proofs=0 duplicate_chunks=1 declined=0"])
            run = analyze.collect_run(root)
            self.assertEqual((run["n_l1"], run["n_l2"]), (2, 2))
            self.assertEqual(run["t0_ms"], 1000)
            self.assertEqual(run["aggregated"], 1)
            self.assertEqual(run["agg_delays_ms"], [790])
            self.assertEqual(run["agg_t50_ms"], 790)
            self.assertIsNone(run["agg_t95_ms"])     # only 1 of 2 L2s finished
            self.assertEqual(run["agg_gap_median_ms"], 290)
            self.assertEqual(run["proof_latency_median_ms"], 400)  # 300, 400, 400
            self.assertEqual(run["ideal_l2_rx"], 2048)
            self.assertAlmostEqual(run["redundancy"], 2560 / 2048)
            self.assertEqual(run["proofs_per_subnet"], 1.0)

            history = analyze.update_history(root, [], append=True)
            analyze.write_html(history, root / "summary.html")
            html = (root / "summary.html").read_text()
            self.assertIn("<svg", html)
            self.assertIn("partial", html)

    def test_parse_event_line(self) -> None:
        ev = analyze.parse_event_line(
            "\x1b[32m INFO\x1b[0m event: EVENT kind=run_end t_ms=5 aggregated=true n=3 x=NA")
        self.assertEqual(ev, {"kind": "run_end", "t_ms": 5, "aggregated": True, "n": 3,
                              "x": None})
        self.assertIsNone(analyze.parse_event_line("no event here"))


class ExportNetvizTests(unittest.TestCase):
    def write_run(self, root: Path) -> None:
        names = ["l1-s00-p0", "l2-000", "l2-001"]
        (root / "run-meta.json").write_text(json.dumps({"mode": "partial", "subnets": 1}))
        (root / "nodes.json").write_text(json.dumps({
            "l1-s00-p0": {"role": "l1", "subnet": 0, "prover": 0, "region": "europe",
                          "up": "25 Mbit", "down": "50 Mbit", "publish_delay_ms": 0},
            "l2-000": {"role": "l2", "region": "asia", "up": "25 Mbit", "down": "50 Mbit"},
            "l2-001": {"role": "l2", "region": "asia", "up": "25 Mbit", "down": "50 Mbit"},
        }))
        (root / "peers.json").write_text(json.dumps({"peers": [
            {"name": n, "peer_id": f"P{i}", "addr": ""} for i, n in enumerate(names)]}))
        gml = ["graph ["]
        for i, n in enumerate(names):
            gml += ["  node [", f"    id {i}", f'    label "{n}"', "  ]"]
        for a, b, lat in ((0, 1, 40), (0, 2, 50), (1, 2, 30)):
            gml += ["  edge [", f"    source {a}", f"    target {b}", f'    latency "{lat} ms"', "  ]"]
        (root / "topology.gml").write_text("\n".join(gml + ["]"]) + "\n")
        tag = "topic=/proofs/1 subnet=0 prover=0"
        write_host(root, "l1-s00-p0", [
            "EVENT kind=proof_published t_ms=1000 t_us=1000000 subnet=0 prover=0 hash=aa bytes=4096",
            f"EVENT kind=wire_send t_ms=1000 t_us=1000010 peer=P1 id=a1 {tag} bytes=48 body=0",
            f"EVENT kind=wire_send t_ms=1100 t_us=1100000 peer=P1 id=b1 {tag} bytes=4200 body=4150",
        ])
        write_host(root, "l2-000", [
            f"EVENT kind=wire_recv t_ms=1040 t_us=1040010 peer=P0 id=a1 {tag} bytes=48 body=0",
            "EVENT kind=proof_committed t_ms=1040 t_us=1040020 subnet=0 prover=0 from=P0",
            f"EVENT kind=wire_recv t_ms=1300 t_us=1300000 peer=P0 id=b1 {tag} bytes=4200 body=4150",
            "EVENT kind=chunk_received t_ms=1300 t_us=1300010 subnet=0 prover=0 from=P0 added=4 dup=0 held=4",
            f"EVENT kind=wire_recv t_ms=1350 t_us=1350000 peer=P2 id=c1 {tag} bytes=4200 body=4150",
            "EVENT kind=chunk_received t_ms=1350 t_us=1350010 subnet=0 prover=0 from=P2 added=0 dup=4 held=4",
            "EVENT kind=aggregate_complete t_ms=1300 t_us=1300020 subnets=1",
        ])
        write_host(root, "l2-001", [
            f"EVENT kind=wire_send t_ms=1320 t_us=1320000 peer=P1 id=c1 {tag} bytes=4200 body=4150",
            f"EVENT kind=wire_send t_ms=1400 t_us=1400000 peer=P1 id=zz {tag} bytes=48 body=0",
        ])

    def test_matches_and_classifies_transfers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_run(root)
            out = root / "trace.ndjson"
            stats = export_netviz.export(root, out)
            lines = [json.loads(line) for line in out.read_text().splitlines()]
            header, events = lines[0], lines[1:]
            self.assertEqual(header["decoderName"], "proof-broadcast")
            self.assertEqual([n["props"]["role"] for n in header["nodes"]], ["l1", "l2", "l2"])
            self.assertEqual(header["meta"]["l2Count"], 2)
            transfers = [e for e in events if e["kind"] == "transfer"]
            self.assertEqual([(t["node"], t["to"], t["layer"]) for t in transfers],
                             [(0, 1, "announce"), (0, 1, "chunk"), (2, 1, "wasted")])
            self.assertEqual(transfers[1]["t"], 100_000)        # relative to first publish
            self.assertEqual(transfers[1]["arrival"], 300_000)
            self.assertEqual(stats["unmatched_sends"], 1)
            edges = {(e["source"], e["target"]): e["latency"] for e in header["edges"]}
            self.assertEqual(edges, {(0, 1): 40_000, (1, 2): 30_000})
            committed = next(e for e in events if e["kind"] == "proof_committed")
            self.assertEqual(committed["from_node"], 0)
            self.assertNotIn("from", committed)


if __name__ == "__main__":
    unittest.main()
