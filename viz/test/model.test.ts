import { describe, expect, it } from 'vitest';
import { parseSubnetList, parseTrace } from '../src/model';
import {
  activeMerges, activeTransfers, countUpTo, isMerging, l2Phase, mergesDone, networkCounts, slotState, subnetsHeld,
} from '../src/state';
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
    expect(l2.merges).toEqual([{ start: 150000, end: 440000, left: [1], right: [0], subnets: [0, 1] }]);
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
