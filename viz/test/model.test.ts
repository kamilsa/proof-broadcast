import { describe, expect, it } from 'vitest';
import { parseSubnetList, parseTrace } from '../src/model';
import {
  activeMerges, activeTransfers, aggregatesFetched, aggregatesPublished, countUpTo, isMerging, l2Phase,
  mergesDone, mergesNeeded, networkCounts, slotState, subnetsHeld,
} from '../src/state';
import { carriesSubnet } from '../src/render';
import { buildTree } from '../src/tree';
import { computeLayout, hitNode, hitSector, l2Order, sectorAngles } from '../src/layout';

const header = {
  v: 1, decoderName: 'proof-broadcast',
  meta: { mode: 'partial', title: 'tiny', subnets: 2, provers_per_subnet: 2, chunk_count: 4, aggregation_ms: 290 },
  nodes: [
    { name: 'l1-s00-p0', props: { role: 'l1', subnet: 0, prover: 0, country: 'europe' } },
    { name: 'l1-s00-p1', props: { role: 'l1', subnet: 0, prover: 1, country: 'asia' } },
    { name: 'l1-s01-p0', props: { role: 'l1', subnet: 1, prover: 0, country: 'europe' } },
    { name: 'l1-s01-p1', props: { role: 'l1', subnet: 1, prover: 1, country: 'europe' } },
    { name: 'l2-000', props: { role: 'l2', country: 'asia' } },
    { name: 'l2-001', props: { role: 'l2', country: 'europe' } },
  ],
  edges: [{ source: 0, target: 4, latency: 20000 }, { source: 4, target: 5, latency: 30000 }],
};

const events = [
  { kind: 'proof_published', t: 0, node: 0, subnet: 0, prover: 0, bytes: 4096 },
  { kind: 'proof_published', t: 1000, node: 1, subnet: 0, prover: 1, bytes: 4096 },
  { kind: 'proof_published', t: 2000, node: 2, subnet: 1, prover: 0, bytes: 4096 },
  { kind: 'proof_published', t: 3000, node: 3, subnet: 1, prover: 1, bytes: 4096 },
  { kind: 'transfer', t: 10, arrival: 20000, node: 0, to: 4, bytes: 40, layer: 'announce', subnet: 0, prover: 0 },
  { kind: 'proof_committed', t: 20001, node: 4, subnet: 0, prover: 0, from_node: 0 },
  { kind: 'proof_declined', t: 25000, node: 4, subnet: 0, prover: 1, from_node: 1 },
  { kind: 'transfer', t: 40000, arrival: 90000, node: 0, to: 4, bytes: 2100, layer: 'chunk', subnet: 0, prover: 0 },
  { kind: 'chunk_received', t: 60000, node: 4, subnet: 0, prover: 0, added: 2, dup: 0, held: 2, from_node: 0 },
  { kind: 'chunk_received', t: 90000, node: 4, subnet: 0, prover: 0, added: 2, dup: 0, held: 4, from_node: 0 },
  { kind: 'proof_complete', t: 90000, node: 4, subnet: 0, prover: 0, subnets_done: 1, from_node: 0 },
  { kind: 'transfer', t: 50000, arrival: 150000, node: 2, to: 4, bytes: 4100, layer: 'chunk', subnet: 1, prover: 0 },
  { kind: 'transfer', t: 60000, arrival: 170000, node: 5, to: 4, bytes: 4100, layer: 'wasted', subnet: 1, prover: 0 },
  { kind: 'proof_committed', t: 45000, node: 4, subnet: 1, prover: 0, from_node: 2 },
  { kind: 'proof_complete', t: 150000, node: 4, subnet: 1, prover: 0, subnets_done: 2, from_node: 2 },
  { kind: 'all_subnets_complete', t: 150000, node: 4 },
  { kind: 'aggregation_started', t: 150000, node: 4, left: 1, right: 1, covered: 2, left_subnets: 1, right_subnets: 0 },
  { kind: 'aggregation_done', t: 440000, node: 4, covered: 2, subnets: '0-1' },
  { kind: 'aggregate_complete', t: 440000, node: 4 },
];

const text = [header, ...events].map(x => JSON.stringify(x)).join('\n');

describe('parseSubnetList', () => {
  it('reads dash lists, bare numbers and none', () => {
    expect(parseSubnetList('3-0-12')).toEqual([0, 3, 12]);
    expect(parseSubnetList(7)).toEqual([7]);
    expect(parseSubnetList('none')).toEqual([]);
    expect(parseSubnetList(undefined)).toEqual([]);
  });
});

describe('model', () => {
  const model = parseTrace(text);
  const l2 = model.l2[4]!;

  it('reads roles, subnets and provers', () => {
    expect(model.l1s).toEqual([0, 1, 2, 3]);
    expect(model.l2s).toEqual([4, 5]);
    expect(model.subnets).toBe(2);
    expect(model.provers).toBe(2);
    expect(model.subnetInfo[0].provers.map(p => p.publishedAt)).toEqual([0, 1000]);
    expect(model.title).toBe('tiny');
  });

  it('tracks each subnet slot of an L2', () => {
    const s0 = l2.slots[0];
    expect([s0.committedAt, s0.heldAt, s0.prover, s0.from, s0.declined]).toEqual([20001, 90000, 0, 0, 1]);
    expect(s0.chunkSteps).toEqual([[60000, 2], [90000, 4]]);
    expect(l2.slots[1].wastedBytes).toBe(4100);
    expect(l2.wastedBytes).toBe(4100);
    expect(l2.rxBytes).toBe(40 + 2100 + 4100 + 4100);
    expect(model.subnetInfo[0].provers[0].holdTimes).toEqual([90000]);
    expect(model.subnetInfo[0].provers[1].holdTimes).toEqual([]);
  });

  it('matches merges with their subnet sets', () => {
    expect(l2.merges).toEqual([{
      start: 150000, end: 440000, left: [1], right: [0], subnets: [0, 1], published: false, kept: true,
    }]);
    expect(model.aggregatedTimes).toEqual([440000]);
    expect(model.milestones.map(m => m.label)).toContain('p50 aggregated');
  });

  it('answers time queries', () => {
    expect(slotState(l2.slots[0], 10000, 4)).toEqual({ kind: 'empty', progress: 0 });
    expect(slotState(l2.slots[0], 70000, 4)).toEqual({ kind: 'fetching', progress: 0.5 });
    expect(slotState(l2.slots[0], 95000, 4)).toEqual({ kind: 'held', progress: 1 });
    expect(l2Phase(l2, 0)).toBe('idle');
    expect(l2Phase(l2, 30000)).toBe('collecting');
    expect(l2Phase(l2, 120000)).toBe('collecting');
    expect(l2Phase(l2, 200000)).toBe('all');
    expect(isMerging(l2, 200000)).toBe(true);
    expect(isMerging(l2, 100000)).toBe(false);
    expect(activeMerges(l2, 200000)).toHaveLength(1);
    expect(mergesDone(l2, 200000)).toBe(0);
    expect(l2Phase(l2, 440000)).toBe('aggregated');
    expect(mergesDone(l2, 440000)).toBe(1);
    expect(subnetsHeld(l2, 100000)).toBe(1);
    expect(l2Phase(model.l2[5]!, 440000)).toBe('idle');
  });

  it('finds transfers in flight and counts traffic', () => {
    expect(activeTransfers(model, 55000).map(t => t.layer)).toEqual(['chunk', 'chunk']);
    expect(activeTransfers(model, 160000).map(t => t.layer)).toEqual(['wasted']);
    const counts = networkCounts(model, 160000, 1);
    expect(counts.l1Published).toBe(4);
    expect(counts.merging).toBe(1);
    expect(counts.all).toBe(1);
    expect(counts.rxBytes).toBe(40 + 2100 + 4100);
    expect(counts.wastedBytes).toBe(0);
    expect(networkCounts(model, 1e9, 0).wastedBytes).toBe(4100);
    expect(countUpTo([1, 2, 2, 5], 2)).toBe(3);
  });

  it('rejects other traces', () => {
    expect(() => parseTrace(JSON.stringify({ ...header, decoderName: 'ec-sim' }))).toThrow(/proof-broadcast/);
  });
});

describe('intermediate aggregates', () => {
  // l2-001 merges {0,1} and publishes it; l2-000 fetches that aggregate,
  // holds subnet 2 on its own, and needs only one merge.
  const aggHeader = {
    ...header,
    meta: { ...header.meta, subnets: 3, intermediate_proofs: true, intermediate_fetch: 'disjoint' },
    nodes: [
      { name: 'l1-s00-p0', props: { role: 'l1', subnet: 0, prover: 0 } },
      { name: 'l1-s01-p0', props: { role: 'l1', subnet: 1, prover: 0 } },
      { name: 'l1-s02-p0', props: { role: 'l1', subnet: 2, prover: 0 } },
      { name: 'l2-000', props: { role: 'l2', l2_index: 0 } },
      { name: 'l2-001', props: { role: 'l2', l2_index: 1 } },
    ],
    edges: [],
  };
  const ev = { committees: '0-1', mask: 3, prover: 1 };
  const aggEvents = [
    { kind: 'proof_published', t: 0, node: 0, subnet: 0, prover: 0, bytes: 4096 },
    { kind: 'aggregation_started', t: 10000, node: 4, left_subnets: 0, right_subnets: 1 },
    { kind: 'aggregation_done', t: 300000, node: 4, subnets: '0-1', kept: true },
    { kind: 'intermediate_published', t: 300000, node: 4, ...ev, covered: 2 },
    { kind: 'transfer', t: 300010, arrival: 320000, node: 4, to: 3, bytes: 40, layer: 'announce', subnet: 65535, ...ev },
    { kind: 'intermediate_committed', t: 320000, node: 3, ...ev, from_node: 4, subsume: false },
    { kind: 'transfer', t: 330000, arrival: 400000, node: 4, to: 3, bytes: 4100, layer: 'chunk', subnet: 65535, ...ev },
    { kind: 'intermediate_chunk_received', t: 400000, node: 3, ...ev, from_node: 4, added: 4, dup: 0, held: 4 },
    { kind: 'intermediate_complete', t: 400000, node: 3, ...ev, from_node: 4, new: '0-1', subnets_done: 2 },
    { kind: 'proof_committed', t: 350000, node: 3, subnet: 2, prover: 0, from_node: 2 },
    { kind: 'proof_complete', t: 410000, node: 3, subnet: 2, prover: 0, subnets_done: 3, from_node: 2 },
    { kind: 'intermediate_declined', t: 420000, node: 3, committees: '1-2', mask: 6, prover: 1, from_node: 4 },
    { kind: 'aggregation_started', t: 410000, node: 3, left_subnets: 2, right_subnets: '0-1' },
    { kind: 'aggregation_done', t: 700000, node: 3, subnets: '0-1-2', kept: true },
    { kind: 'aggregate_complete', t: 700000, node: 3 },
  ];
  const model = parseTrace([aggHeader, ...aggEvents].map(x => JSON.stringify(x)).join('\n'));
  const fetcher = model.l2[3]!;
  const producer = model.l2[4]!;

  it('marks the producer’s published merge', () => {
    expect(model.intermediates).toBe(true);
    expect(producer.merges[0].published).toBe(true);
    expect(producer.published).toEqual([{ t: 300000, committees: [0, 1] }]);
  });

  it('fills the fetcher’s slots from the aggregate', () => {
    expect(fetcher.fetched).toHaveLength(1);
    const f = fetcher.fetched[0];
    expect([f.key, f.origin, f.committedAt, f.heldAt, f.from, f.saves]).toEqual(['0-1', 4, 320000, 400000, 4, 1]);
    for (const s of [0, 1]) {
      const slot = fetcher.slots[s];
      expect([slot.via, slot.origin, slot.committedAt, slot.heldAt, slot.prover]).toEqual(['aggregate', 4, 320000, 400000, -1]);
      expect(slot.chunkSteps).toEqual([[400000, 4]]);
    }
    expect(fetcher.slots[2].via).toBe('leaf');
    expect(slotState(fetcher.slots[0], 350000, 4)).toEqual({ kind: 'fetching', progress: 0 });
    expect(model.subnetInfo[0].aggHoldTimes).toEqual([400000]);
    expect(model.subnetInfo[0].heldTimes).toEqual([400000]);
    expect(fetcher.aggDeclined).toBe(1);
  });

  it('counts merges against what is left to do', () => {
    expect(mergesNeeded(model, fetcher, 0)).toBe(2);
    expect(mergesNeeded(model, fetcher, 500000)).toBe(1);
    expect(mergesDone(fetcher, 700000)).toBe(1);
    expect(aggregatesFetched(fetcher, 500000)).toBe(1);
    expect(aggregatesPublished(producer, 300000)).toBe(1);
    expect(networkCounts(model, 1e9, 0)).toMatchObject({ aggPublished: 1, aggFetched: 1 });
  });

  it('tags aggregate transfers with their committees', () => {
    const tr = model.transfers.find(x => x.layer === 'chunk')!;
    expect([tr.subnet, tr.prover, tr.committees]).toEqual([-1, 1, [0, 1]]);
    expect(carriesSubnet(tr, 1)).toBe(true);
    expect(carriesSubnet(tr, 2)).toBe(false);
  });

  it('logs aggregate events under every committee', () => {
    const commit = model.logs.find(l => l.text.startsWith('Fetching aggregate'))!;
    expect(commit.subnets).toEqual([0, 1]);
    expect(commit.text).toContain('by l2-001');
  });

  it('builds the tree with the fetched aggregate as a leaf', () => {
    const tree = buildTree(model, fetcher);
    expect(tree.leaves.map(l => l.key).sort()).toEqual(['0-1', '2']);
    expect(tree.roots).toHaveLength(1);
    expect(tree.roots[0].subnets).toEqual([0, 1, 2]);
    expect(tree.missing).toEqual([]);
  });
});

describe('gossipsub-chunked', () => {
  // l2-000 relays S0·p0 (first chunk seen) but S0·p1 completes first and is
  // the one it uses; p0's last chunk arrives later and is unused.
  const chunkedHeader = {
    ...header,
    meta: { ...header.meta, mode: 'gossipsub-chunked', subnets: 1, chunk_count: 2 },
    nodes: header.nodes.slice(0, 2).concat([{ name: 'l2-000', props: { role: 'l2', country: 'asia' } }]),
    edges: [],
  };
  const chunk = (t: number, prover: number, index: number, held: number, relayed: boolean) => ({
    kind: 'chunk_received', t, node: 2, subnet: 0, prover, index, added: 1, dup: 0, held, relayed, from_node: prover,
  });
  const chunkedEvents = [
    { kind: 'proof_published', t: 0, node: 0, subnet: 0, prover: 0, bytes: 4096 },
    { kind: 'proof_committed', t: 100, node: 2, subnet: 0, prover: 0, from_node: 0 },
    chunk(100, 0, 0, 1, true),
    { kind: 'proof_declined', t: 200, node: 2, subnet: 0, prover: 1, from_node: 1 },
    chunk(200, 1, 0, 1, false),
    chunk(300, 1, 1, 2, false),
    { kind: 'proof_complete', t: 300, node: 2, subnet: 0, prover: 1, from_node: 1, subnets_done: 1, relayed: false },
    chunk(400, 0, 1, 2, true),
    { kind: 'proof_unused', t: 400, node: 2, subnet: 0, prover: 0, from_node: 0, relayed: true },
  ];
  const model = parseTrace([chunkedHeader, ...chunkedEvents].map(x => JSON.stringify(x)).join('\n'));
  const slot = model.l2[2]!.slots[0];

  it('separates the relayed prover from the used one', () => {
    expect([slot.relayProver, slot.prover, slot.heldAt, slot.declined]).toEqual([0, 1, 300, 1]);
  });

  it('tracks the best proof’s chunk progress without logging every chunk', () => {
    expect(slot.chunkSteps).toEqual([[100, 1], [300, 2]]);
    expect(slotState(slot, 250, 2)).toEqual({ kind: 'fetching', progress: 0.5 });
    const kinds = model.logs.map(l => l.text.split(' ')[0]);
    expect(kinds).toEqual(['Published', 'Fetching', 'Declined', 'Holds', 'Assembled']);
    expect(model.logs.find(l => l.kind === 'held')!.text).toContain('not the one it relays');
  });
});

describe('layout', () => {
  const model = parseTrace(text);
  const order = l2Order(model, 'finish');
  const layout = computeLayout(model, 800, 600, order);

  it('puts the fastest aggregator at the centre and L1s on their sector', () => {
    expect(order).toEqual([4, 5]);
    expect(Math.hypot(layout.x[4] - 400, layout.y[4] - 300)).toBeLessThan(
      Math.hypot(layout.x[5] - 400, layout.y[5] - 300));
    for (const i of model.l1s) {
      const d = Math.hypot(layout.x[i] - layout.cx, layout.y[i] - layout.cy);
      expect(d).toBeCloseTo(layout.ringR, 5);
      const node = model.nodes[i];
      const [a0, a1] = sectorAngles(node.subnet, model.subnets);
      let angle = Math.atan2(layout.y[i] - layout.cy, layout.x[i] - layout.cx);
      while (angle < a0) angle += 2 * Math.PI;
      expect(angle).toBeLessThanOrEqual(a1);
    }
  });

  it('hit-tests nodes and sectors', () => {
    expect(hitNode(layout, layout.x[2], layout.y[2])).toBe(2);
    expect(hitNode(layout, 5, 5)).toBe(-1);
    expect(hitSector(layout, layout.x[3], layout.y[3])).toBe(1);
    expect(hitSector(layout, layout.cx, layout.cy)).toBe(-1);
  });
});
