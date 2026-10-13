# proof-broadcast-tree

Rust + rust-libp2p simulator of **leanVM proof aggregation along a tree**, run
under [Shadow](https://shadow.github.io/) (native or Docker). It is a
single-mode sibling of `../proof-broadcast`, with the same launcher UX
(`uv run shadow-sim.py`), the same seeded topology and regions, and the same
analyzer style. It uses **no gossipsub**: peers handshake, announce which
chunks they hold, and pull missing proofs chunk by chunk over a single
request-response protocol. A peer relays a proof while still downloading it,
and serves each proof to at most `fanout` peers at a time.

## Model

- **L1 provers**: `subnets × provers_per_subnet` (default 16 × 4). Each
  produces one distinct subnet proof (default 300 KiB).
- **Aggregation tree**: the subnets are its leaves. Each level groups
  consecutive items `aggregation_arity` at a time. A group of two or more
  becomes a tree node; a trailing single item moves up a level unchanged.
  Node ids run level by level, left to right (level 0 is the bottom), so the
  root comes last.

  | subnets, arity | tree nodes per level | depth |
  |---|---|---|
  | 16, 2 | 8 + 4 + 2 + 1 = 15 | 4 |
  | 16, 4 | 4 + 1 = 5 | 2 |
  | 5, 2  | {0,1} {2,3} → {0..3} → root = {0..3} + subnet 4 | 3 |
  | 4, 8  | one root over all four subnets | 1 |

- **L2 aggregators** (default 64): each aggregates for the tree node its
  **PeerId** maps to: `u64_le(sha256(peer_id)[..8]) % tree_nodes`. Any peer
  can therefore tell which node a connected L2 serves. The assignment is
  uniform per tree node, so a node can end up with no aggregator. The
  launcher warns about that and records it in `run-meta.json`, and it
  refuses configs with fewer L2s than tree nodes.
- **Aggregation**: an L2 holds one proof per input of its node (subnet
  proofs at the bottom, child aggregates above). It then runs **one k→1
  recursion**, taking `aggregation_ms` whatever the input count (default
  290 ms, from leanVM's 2→1 figure), and announces the aggregate to the
  aggregators of its parent node. At the root, that aggregate is the
  **global proof** (`aggregate_complete`, the headline). It is not broadcast
  further.
- **Timeline**: all processes start together. During `warmup_secs` peers
  connect and handshake. After that, each L1 publishes at a seeded uniform
  delay in `[0, proof_jitter_ms]`. Every node exits `observe_secs` after the
  warmup ends.

## Protocol `/proof-tree/1`

libp2p `request_response` with a bincode codec (each frame is a `u32` LE
length followed by bincode):

| request | response | when |
|---|---|---|
| `Hello { role, subnet }` | `Ack` | both sides, on connect |
| `Have { proofs: [{id, chunk bitmap}] }` | `Interest { unwanted }` | to our downstream peers as our chunks of a proof grow; to our sources once we complete it |
| `GetChunk { hash, index }` | `Chunk { data }` / `Missing` / `Busy` | requester pulling a proof |

- **Fan-out.** Every proof a peer holds, completely or in part, is announced
  and served to at most `fanout` peers at a time (default 8): its downstream
  set. The set is filled from connected peers whose tree node takes the proof
  as input: an L1's consumer node, an aggregator's node-mates for its inputs,
  its parent node for its aggregate. Candidates are tried in a pseudo-random
  order that differs for each proof. A slot frees when its peer holds the
  proof (a full `Have`), lists it as unwanted in `Interest` (it chose another
  proof for that input, or already has it), or disconnects; the next
  candidate is then offered the proof. A `GetChunk` from a peer outside a
  full set gets `Busy`.
- **Pulling.** An L2 commits to the first proof announced for each input
  slot and declines any other proof for that slot, so it never downloads two
  proofs covering the same input. Every peer that announced the committed
  proof is a holder, together with the chunks it holds. Each missing chunk
  is requested from the least loaded holder that has it, with at most
  `max_inflight_per_peer` outstanding per peer (default 64, a whole proof
  pipelined from one holder). Timeouts, `Missing`/`Busy` answers and
  disconnects re-queue the chunk. Proofs are verified against their SHA-256.
  On completion an L2 sends a full `Have` to each of its sources, which frees
  its slot there and makes it a new holder for sources still downloading.
- **Cut-through.** A peer serves chunks of a proof it is still downloading,
  and announces its growing bitmap to its downstream peers. Updates are
  batched over `have_interval_ms` (default 10 ms).

## Topology

The launcher asks the binary for the tree and every host's PeerId and tree
node (`proof-broadcast-tree --dump-tree --subnets S --aggregation-arity k
--dump-peer-ids <seeds>`). It then wires peers along the tree (connections
are two-way):

- an L1 dials up to `l1_peers_per_node` aggregators of the node consuming
  its subnet;
- an L2 dials up to `tree_mates_per_node` aggregators of its own node and up
  to `tree_parent_peers` of its parent node. Its children reach it through
  their own parent links.

Bandwidth is set per role (`[network.l1]`, `[network.l2]`). The optional
`[network.l1_supernodes]` and `[network.l2_supernodes]` sections give a
seeded, exact `fraction` of that role their own bandwidth; `nodes.json` marks
those hosts with `supernode`.

## Run

```text
uv run shadow-sim.py                 # build + run proofsim.toml (native runner)
uv run shadow-sim.py my.toml         # another config (e.g. aggregation_arity = 4)
uv run shadow-sim.py --dry-run       # build + generate shadow.yaml / topology.gml only
uv run shadow-sim.py --clean         # wipe shadow.data/, history, summary.html
uv run shadow-sim.py --serve         # run, then serve summary.html on :4321
python3 scripts/analyze.py shadow-output   # re-summarize an existing run
```

Because the tree and the PeerIds come from the binary, even `--dry-run`
builds it (`cargo build --release`, or the Docker image, which is arm64 only).
Each run writes these files to `<output.dir>`:

- `tree.json`: the tree nodes.
- `nodes.json`: every host's role, subnet, tree node, level, committees,
  region and publish delay.
- `peers.json`: PeerId → host.
- `run-meta.json`: settings plus tree shape, aggregators per node and empty
  nodes.

Host logs are in `<output.dir>/shadow.data/hosts/<host>/proof-broadcast-tree.1000.stdout`.
Hosts are named `l1-sSS-pP` and `l2-NNN`. Each run is appended to
`runs-history.json`, and `summary.html` is rewritten from it.

The CLI summary reports:

- **Global proof**: when the first root aggregator holds it, plus the median
  and max over root aggregators.
- **Per level**: *first* is the first node aggregate. *Ready* is when every
  node of the level has at least one aggregate. *t50* is the median over the
  level's aggregators, alongside the median time to hold all inputs.
- **Hop latency**: the time from a proof existing to an aggregator that
  needs it holding all of it.
- **Bytes**: L1 upload (as a multiple of proof size) and L2 rx/tx.
- **Fan-out**: the peak downstream set, peers per served proof, how many L2s
  relayed, and the share of served chunks sent while still arriving.
- **Errors**: chunk failures, duplicates and `Missing` answers.

## Events

`EVENT kind=<kind> t_ms=<shared Shadow clock> k=v ...`:

- `tree_assigned` (L2: `node= level= committees= inputs= parent= root=`)
- `peer_hello` (`peer= role= subnet= node=`)
- `warmup_complete`
- `proof_published` (L1: `consumer= peers=`)
- `proof_committed` (`peer_chunks=` the announcer held) / `proof_declined` /
  `chunk_received` / `proof_complete` (`sources=`) for subnet proofs
- `proof_offered` (`peers=` newly added downstream, `downstream= held=`)
- `intermediate_*` equivalents for child aggregates (`committees= mask=`)
- `inputs_complete`
- `aggregation_started` (`input_subnets=0-1/2-3`) / `aggregation_done`
- `node_aggregate_complete` (`node= level=`)
- `aggregate_complete` (root only)
- `proof_served` at exit, per proof we sent chunks of (`peers=` distinct
  peers, `chunks=`)
- `bytes` (`tx rx tx_data rx_data`)
- `run_end`

`run_end` carries `declined`, `haves_sent`, `haves_received`,
`chunk_requests`, `chunk_failures`, `chunks_received`, `duplicate_chunks`,
`chunks_served`, `chunks_served_partial` (cut-through), `chunks_missing`,
`chunks_refused` (`Busy`), `fanout`, `fanout_peak` (most downstream peers of
one proof at once) and `max_peers_per_proof`.

## Not (yet) modelled

- a fallback when a tree node has no aggregator or stalls
- broadcasting the global proof beyond the root aggregators
- the visualizer from `../proof-broadcast`

## Tests

```text
cargo test                              # unit + in-process QUIC end-to-end trees
python3 -m unittest tests/test_shadow_sim.py
```
