# proof-broadcast

Rust + rust-libp2p simulator of **leanVM proof propagation** in a post-quantum
Ethereum network, run under [Shadow](https://shadow.github.io/) (Docker or
native). It follows ec-sim's structure: the same `uv run shadow-sim.py` launcher
UX and the same patched gossipsub (partial messages, per-topic byte counters).

## Model

- **L1 provers**: `subnets × provers_per_subnet` (default 16 × 4 = 64). Each
  publishes one distinct proof (default 300 KiB) to the global `/proofs/1`
  topic. They **never subscribe** to it, so they publish through gossipsub
  fanout (`proofs_mesh_n` peers) and never relay.
- **L2 provers** (default 64) need **one proof per subnet**. An L2 never fetches
  or relays two different proofs from the same subnet (`SubnetLedger`).
- **Aggregation**: an L2 merges its proofs pairwise with leanVM **2→1
  recursion** as they arrive. Each merge takes `aggregation_ms` (default 290 ms,
  from leanVM's README: *recursion 2→1*, 0.287 s on an M4 Max), with at most
  `aggregation_workers` merges at once. 16 subnets always need 15 merges. The
  headline metric is when the L2 finishes its aggregate (`aggregate_complete`).
- **Timeline**: all processes start together. After `warmup_secs`, each L1
  publishes at a seeded uniform delay in `[0, proof_jitter_ms]`. Every node
  exits `observe_secs` after the warmup ends.

## Modes

| `[sim].mode` | Wire | L2 rule |
|---|---|---|
| `gossipsub` | Whole proof as one gossipsub message on `/proofs/1` | Accept (forward) the first proof per subnet; later ones are *Ignored* (not forwarded), but they were already downloaded |
| `partial` | Gossipsub 1.3 partial messages; proof split into `chunk_count` chunks (default 64) | Group id = `ProofId` (subnet, prover, size, chunks, hash). The L1 advertises a have-bitmap. An L2 commits to the first proof per subnet that a peer holds chunks of, and requests all chunks. It never requests a second proof from that subnet |

In `partial` mode an L2 advertises the chunks it holds as they arrive, so it
serves the proof it committed to to its mesh. Several holders can answer the
same request at once. The resulting duplicate chunks are counted
(`duplicate_chunks`), and no request striping is attempted yet.

## Intermediate proofs

With `intermediate_proofs = true`, L2s also share their partial aggregates, as
the EIP's proof aggregators do on `recursive_aggregation`. Works in both modes.

- **Publishing**: when a 2→1 recursion finishes with a result covering at
  least `intermediate_min_committees` committees (default 2), the L2 publishes
  it on `/proofs/1`. The final aggregate (all committees) is never published.
  An aggregate is the same size as a subnet proof.
- **Identity**: a proof covers a committee bitmask (`subnets <= 64`). The group
  id / gossip message carries `subnet || prover || committees`. Aggregates
  use `subnet = 65535` and `prover` = the producing L2's index (`l2-NNN`).
- **Fetching** (`intermediate_fetch`): an L2 never holds two proofs covering
  the same committee.
  - `disjoint`: fetch only proofs whose committees are disjoint from
    everything it holds, is merging or is downloading.
  - `subsume`: also fetch a proof that fully contains some held items, as long
    as it adds a new committee and splits no held item or running merge, and
    overlaps no download (partial-message requests cannot be withdrawn). The
    contained items are frozen until it arrives, then dropped
    (`item_dropped`). A merge still running then is discarded when it ends.
- A fetched aggregate enters the L2's pool like a subnet proof, so the L2 runs
  fewer recursions (`merges_run`, `subnets − 1` without intermediates).

Fetching only pays off when proofs arrive slowly relative to the merge time
(bandwidth-bound links). On localhost every L2 holds every subnet proof long
before any aggregate appears, so aggregates are only declined.

## Run

```text
uv run shadow-sim.py                 # build image (if needed) + run proofsim.toml
uv run shadow-sim.py my.toml         # another config (e.g. mode = "partial")
uv run shadow-sim.py --dry-run       # generate shadow.yaml / topology.gml only
uv run shadow-sim.py --rebuild       # force docker build
uv run shadow-sim.py --clean         # wipe shadow.data/, history, summary.html
uv run shadow-sim.py --serve         # run, then serve summary.html on :4321
python3 scripts/analyze.py shadow-output   # re-summarize an existing run
```

Each run is appended to `<output.dir>/runs-history.json`, and
`<output.dir>/summary.html` is rewritten from it. It shows aggregate and
collection completion CDFs, bytes, redundancy (median L2 rx ÷ `subnets ×
proof_size`), duplicate chunks, and distinct proofs used per subnet. Host logs
are in `<output.dir>/shadow.data/hosts/<host>/proof-broadcast.1000.stdout`.
Hosts are named `l1-sSS-pP` and `l2-NNN`. `nodes.json` records every host's
role, subnet, region and publish delay.

## Visualizer (`viz/`)

A dedicated viewer for these traces, built around subnets and L2 aggregators:

```text
uv run shadow-sim.py --netviz-trace     # writes <output.dir>/proof-broadcast.netviz.ndjson
cd viz && bun install && bun dev        # http://localhost:5188
```

The dev server lists every `shadow-output*/*.netviz.ndjson` in the toolbar
(`?trace=<dir>/<file>` opens one directly). You can also drop or load a file.
`bun run build` makes a static copy in `viz/dist` that loads files you drop or
pick.

- **Subnet wheel**: the L1 provers sit on the outer ring, in one coloured
  sector per subnet. The ring around each L1 shows the share of L2s that chose
  its proof. The arc inside each sector shows how many L2s already hold that
  subnet.
- **L2 aggregators** fill the centre, fastest finishers in the middle
  (placement can switch to region or name). Each L2 is a donut with one segment
  per subnet, pointing at that subnet's sector. A segment fills as the chunks
  arrive, in the shade of the prover it chose. The core shows the stage:
  collecting, all subnets held, or aggregated (✓). A pulsing gold ring means a
  2→1 recursion is running, and the gold wedge counts finished merges.
- **Particles** carry the subnet's colour; wasted transfers have an orange
  head. The **Outcome** toggle recolours them as used or wasted. Announcements
  and requests are hidden by default.
- **Focus**: hover or click a subnet (on the wheel or in the list) to show only
  that subnet. Click an L2 to highlight its links and traffic.
- **Panels**: the subnet list shows provers published and L2s holding the
  subnet, split by chosen prover. The completion chart shows the all-subnets
  and aggregated CDFs. The aggregator matrix is L2 × subnet over time, with
  merge progress.
  - **Detail**: an L2's time-ordered aggregation tree (fetch → held → waiting →
    each 2→1 recursion, taken from the logged merge subnets) and its per-subnet
    table.
  - **Log**: filtered by the current selection.
- **Intermediate proofs**: aggregates exchanged between L2s are ivory particles
  with a larger head. A subnet held inside a fetched aggregate is a darker,
  outlined donut segment (an ivory stripe in the matrix, an `agg l2-NNN` row
  in the subnet table). In the tree a fetched aggregate is an ivory leaf
  column, and a published merge is ringed in ivory. The merge count is out of
  the merges still needed after fetches.

Keys: Space play/pause, ←/→ step 50 ms (Shift: 500 ms), Home restart, Esc clear.

## NetVis visualization

`uv run shadow-sim.py --netviz-trace` exports
`<output.dir>/proof-broadcast.netviz.ndjson` after each run
(`proof-broadcast-<i>.netviz.ndjson` for multi-run configs). An existing run can
be exported with `python3 scripts/export_netviz.py <output.dir> [dest]`. Load the
file in [netviz](../netviz). Its bundled `proof-broadcast` decoder is picked
automatically from the header.

- **Nodes** have these states: idle → *L1 published*, and for L2 provers
  *collecting* → *all subnets* → *aggregated*. Rings show subnets held
  (out of `subnets`) and finished 2→1 merges (out of `subnets − 1`).
- **Particles** come from the patched gossipsub trace hook (`wire_send` /
  `wire_recv`, tagged with the proof's subnet and prover). Each travels from its
  observed send to its observed receive time, and its colour shows what the
  receiver did with it:
  - *proof*: a whole proof that was used.
  - *chunks*: a partial body that added chunks.
  - *announce / request*: a metadata-only partial.
  - *wasted*: a redundant proof, a gossipsub duplicate, or an all-duplicate
    chunk body.
- **Charts**: the CDF counts L2 provers that finished their aggregate. The
  timeline marks the first and last publish, and p50/p95 for all-subnets and
  aggregated. The event log narrates commits, declines, chunk arrivals and
  merges per node.

## Events

`EVENT kind=<kind> t_ms=<shared Shadow clock> k=v ...`: `warmup_complete`,
`proof_published`, `proof_received` (gossipsub, `redundant=`),
`proof_committed` / `proof_declined` / `chunk_received` (partial),
`proof_complete`, `all_subnets_complete`, `aggregation_started`
(`left_subnets=0-3 right_subnets=5`), `aggregation_done` (`subnets=0-3-5
kept=`), `aggregate_complete`, `bytes`, `run_end`.

Intermediate proofs add `intermediate_published`, `intermediate_received`
(gossipsub, `redundant= subsume=`), `intermediate_committed` (`subsume=`) /
`intermediate_declined` / `intermediate_chunk_received` (partial),
`intermediate_complete` (`new=` committees it added) and `item_dropped`. Each
carries `committees=0-1-5 mask=<u64> prover=<L2 index> hash=`. `run_end` adds
`intermediates_published`, `intermediates_fetched`, `intermediates_declined`,
`merges_run`, `merges_discarded` and `items_dropped`. Wire events
(`wire_send` / `wire_recv`) carry `mask=` too.

## Tests

```text
cargo test                              # unit + in-process QUIC end-to-end (both modes)
python3 -m unittest tests/test_shadow_sim.py
```
