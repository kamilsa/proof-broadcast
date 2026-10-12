// Trace model for proof-broadcast NetVis traces (`*.netviz.ndjson`, written
// by scripts/export_netviz.py). Everything is precomputed once on load; the
// per-frame queries in state.ts only binary-search these arrays.

export type Role = 'l1' | 'l2';
export type Layer = 'proof' | 'chunk' | 'announce' | 'wasted';
export const LAYERS: Layer[] = ['proof', 'chunk', 'announce', 'wasted'];

export interface NodeInfo {
  idx: number;
  name: string;
  role: Role;
  /** L1 only (−1 for L2). */
  subnet: number;
  prover: number;
  region: string;
}

export interface Transfer {
  from: number;
  to: number;
  /** Microseconds since the first publish. */
  t: number;
  arrival: number;
  bytes: number;
  layer: Layer;
  /** Proven subnet; −1 for an intermediate aggregate. */
  subnet: number;
  /** L1 prover index, or the producing L2's index for an aggregate. */
  prover: number;
  /** Committees the carried proof covers (one entry for a subnet proof). */
  committees: number[];
}

/** `subnet` value of an intermediate aggregate in the node's events. */
export const AGGREGATE_SUBNET = 65535;

/** How an L2 came to hold a subnet. */
export type SlotSource = '' | 'leaf' | 'aggregate';

/** One L2's view of one subnet. Times are NaN until they happen. */
export interface SubnetSlot {
  committedAt: number;
  heldAt: number;
  /** Prover whose proof the L2 chose (−1 until chosen, or via an aggregate). */
  prover: number;
  /** Node that delivered the final part of the proof. */
  from: number;
  /** Whether the subnet came in its own proof or inside a fetched aggregate. */
  via: SlotSource;
  /** Via an aggregate: the L2 node that produced it (−1 if unknown). */
  origin: number;
  /** Via an aggregate: its committee key (`0-1-5`). */
  aggKey: string;
  /** Partial mode: (time, chunks held) steps. */
  chunkSteps: Array<[number, number]>;
  /** Other proofs of this subnet the L2 turned down (partial) or received anyway (gossipsub). */
  declined: number;
  redundant: number;
  wastedBytes: number;
  usefulBytes: number;
}

export interface Merge {
  start: number;
  end: number;
  left: number[];
  right: number[];
  /** Union of left and right, sorted. */
  subnets: number[];
  /** The result was advertised to other L2s as an intermediate proof. */
  published: boolean;
  /** False if the result was discarded (subsumed while running). */
  kept: boolean;
}

/** Another L2's intermediate aggregate this L2 fetched (or started to). */
export interface FetchedAggregate {
  key: string;
  committees: number[];
  /** Producing L2 node (−1 if unknown). */
  origin: number;
  committedAt: number;
  heldAt: number;
  from: number;
  /** It replaced items the L2 already held. */
  subsume: boolean;
  /** 2→1 recursions it spares the L2 (newly covered committees − 1). */
  saves: number;
}

export interface L2Timeline {
  node: number;
  slots: SubnetSlot[];
  merges: Merge[];
  fetched: FetchedAggregate[];
  /** Own aggregates advertised to other L2s. */
  published: Array<{ t: number; committees: number[] }>;
  /** Items dropped for a subsuming aggregate. */
  dropped: Array<{ t: number; subnets: number[] }>;
  /** Other L2s' aggregates turned down (or received anyway, gossipsub). */
  aggDeclined: number;
  /** 2→1 recursions this L2 does not need thanks to fetched aggregates. */
  mergesSaved: number;
  allSubnetsAt: number;
  aggregatedAt: number;
  firstHeldAt: number;
  rxBytes: number;
  wastedBytes: number;
}

export interface ProverInfo {
  node: number;
  subnet: number;
  prover: number;
  publishedAt: number;
  /** Sorted times at which an L2 finished holding this prover's proof. */
  holdTimes: number[];
}

export interface SubnetInfo {
  subnet: number;
  provers: ProverInfo[];
  /** Sorted times at which each L2 first held this subnet. */
  heldTimes: number[];
  /** Sorted times at which an L2 first held it inside a fetched aggregate. */
  aggHoldTimes: number[];
}

export interface LogEntry {
  t: number;
  node: number;
  subnet: number;
  /** Aggregate entries: every committee involved (for subnet filtering). */
  subnets?: number[];
  kind: string;
  text: string;
}

export interface Milestone {
  t: number;
  label: string;
  kind: 'publish' | 'all' | 'aggregated';
}

export interface Model {
  title: string;
  mode: string;
  meta: Record<string, unknown>;
  subnets: number;
  provers: number;
  chunkCount: number;
  aggregationMs: number;
  /** L2s published intermediate aggregates in this run. */
  intermediates: boolean;
  nodes: NodeInfo[];
  l1s: number[];
  l2s: number[];
  /** Indexed by node; undefined for L1s. */
  l2: Array<L2Timeline | undefined>;
  subnetInfo: SubnetInfo[];
  /** Sorted by send time. */
  transfers: Transfer[];
  /** Longest send→arrival interval, bounds the active-transfer scan. */
  maxFlight: number;
  /** Transfer indices per receiving node, sorted by arrival. */
  inbound: number[][];
  edges: Array<{ a: number; b: number; latencyUs: number }>;
  logs: LogEntry[];
  milestones: Milestone[];
  /** Sorted L2 completion times. */
  allSubnetsTimes: number[];
  aggregatedTimes: number[];
  /** Arrival-sorted cumulative received / wasted bytes (whole network). */
  arrivals: Float64Array;
  rxCum: Float64Array;
  wastedCum: Float64Array;
  end: number;
}

interface RawEvent {
  kind: string;
  t: number;
  node: number;
  [key: string]: unknown;
}

const num = (v: unknown, fallback = 0): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback;

/** Subnet lists are logged as `0-3-5` (`none` when empty); a single subnet
 * may already have been turned into a number by the exporter. */
export function parseSubnetList(v: unknown): number[] {
  if (typeof v === 'number' && Number.isInteger(v)) return [v];
  if (typeof v !== 'string' || v === 'none' || v === '') return [];
  return v.split('-').map(Number).filter(Number.isInteger).sort((a, b) => a - b);
}

function emptySlot(): SubnetSlot {
  return {
    committedAt: NaN, heldAt: NaN, prover: -1, from: -1, via: '', origin: -1, aggKey: '',
    chunkSteps: [], declined: 0, redundant: 0, wastedBytes: 0, usefulBytes: 0,
  };
}

/** Committees of a transfer or aggregate event: the `committees` list, else
 * the subnet itself for a subnet proof. */
function committeesOf(ev: Record<string, unknown>): number[] {
  const list = parseSubnetList(ev.committees);
  if (list.length) return list;
  const subnet = num(ev.subnet, -1);
  return subnet >= 0 && subnet !== AGGREGATE_SUBNET ? [subnet] : [];
}

function kib(bytes: number): string {
  return `${Math.round(bytes / 1024)} KiB`;
}

function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return NaN;
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * p) - 1))];
}

export function parseTrace(text: string): Model {
  const lines = text.split('\n').filter(line => line.trim().length > 0);
  if (!lines.length) throw new Error('Empty trace');
  const header = JSON.parse(lines[0]);
  if (header.v !== 1 || header.decoderName !== 'proof-broadcast') {
    throw new Error(`Not a proof-broadcast trace (decoderName=${header.decoderName})`);
  }
  const events: RawEvent[] = lines.slice(1).map(line => JSON.parse(line));
  return buildModel(header, events);
}

export function buildModel(
  header: { nodes: Array<{ name: string; props?: Record<string, unknown> }>; edges?: Array<{ source: number; target: number; latency: number }>; meta?: Record<string, unknown> },
  rawEvents: RawEvent[],
): Model {
  const meta = header.meta ?? {};
  const nodes: NodeInfo[] = header.nodes.map((n, idx) => {
    const props = n.props ?? {};
    const role: Role = props.role === 'l1' ? 'l1' : 'l2';
    return {
      idx, name: n.name, role,
      subnet: role === 'l1' ? num(props.subnet, 0) : -1,
      prover: role === 'l1' ? num(props.prover, 0) : -1,
      region: String(props.country ?? ''),
    };
  });
  const l1s = nodes.filter(n => n.role === 'l1').map(n => n.idx);
  const l2s = nodes.filter(n => n.role === 'l2').map(n => n.idx);
  const maxL1Subnet = l1s.reduce((m, i) => Math.max(m, nodes[i].subnet + 1), 0);
  const subnets = Math.max(1, num(meta.subnets, maxL1Subnet || 1));
  const provers = Math.max(1, num(meta.provers_per_subnet,
    l1s.reduce((m, i) => Math.max(m, nodes[i].prover + 1), 1)));
  const chunkCount = Math.max(1, num(meta.chunk_count, 64));
  const mode = String(meta.mode ?? 'gossipsub');
  const n = nodes.length;
  const valid = (i: unknown): i is number => typeof i === 'number' && Number.isInteger(i) && i >= 0 && i < n;

  const l2: Array<L2Timeline | undefined> = nodes.map(node => node.role === 'l2'
    ? {
      node: node.idx, slots: Array.from({ length: subnets }, emptySlot), merges: [],
      fetched: [], published: [], dropped: [], aggDeclined: 0, mergesSaved: 0,
      allSubnetsAt: NaN, aggregatedAt: NaN, firstHeldAt: NaN, rxBytes: 0, wastedBytes: 0,
    }
    : undefined);
  // An aggregate's `prover` is its producer's L2 index (`l2_index` prop).
  const l2ByIndex = new Map<number, number>();
  header.nodes.forEach((n, idx) => {
    const index = n.props?.l2_index;
    if (nodes[idx].role === 'l2' && typeof index === 'number') l2ByIndex.set(index, idx);
  });
  const originOf = (ev: RawEvent) => l2ByIndex.get(num(ev.prover, -1)) ?? -1;

  const subnetInfo: SubnetInfo[] = Array.from({ length: subnets }, (_, subnet) => ({
    subnet, provers: [], heldTimes: [], aggHoldTimes: [],
  }));
  for (const i of l1s) {
    const node = nodes[i];
    if (node.subnet < subnets) {
      subnetInfo[node.subnet].provers.push({
        node: i, subnet: node.subnet, prover: node.prover, publishedAt: NaN, holdTimes: [],
      });
    }
  }
  for (const info of subnetInfo) info.provers.sort((a, b) => a.prover - b.prover);
  const proverInfo = (subnet: number, prover: number) =>
    subnetInfo[subnet]?.provers.find(p => p.prover === prover);

  const transfers: Transfer[] = [];
  const logs: LogEntry[] = [];
  const publishTimes: number[] = [];
  const pending: Array<Merge | undefined>[] = nodes.map(() => []);
  const log = (t: number, node: number, subnet: number, kind: string, text: string, list?: number[]) =>
    logs.push(list ? { t, node, subnet, subnets: list, kind, text } : { t, node, subnet, kind, text });
  const tag = (ev: RawEvent) => `S${num(ev.subnet)}·p${num(ev.prover)}`;
  const nameOf = (i: unknown) => (valid(i) ? nodes[i].name : '?');
  const aggTag = (ev: RawEvent, list: number[]) => {
    const origin = originOf(ev);
    return `{${list.join(',')}} by ${origin >= 0 ? nodes[origin].name : `L2 #${num(ev.prover)}`}`;
  };
  /** The aggregate an L2 is fetching, created on first sight. */
  const fetchedAgg = (timeline: L2Timeline, ev: RawEvent, list: number[], t: number) => {
    const key = list.join('-');
    let agg = timeline.fetched.find(f => f.key === key && f.origin === originOf(ev));
    if (!agg) {
      agg = {
        key, committees: list, origin: originOf(ev), committedAt: t, heldAt: NaN, from: -1,
        subsume: ev.subsume === true, saves: 0,
      };
      timeline.fetched.push(agg);
      for (const s of list) {
        const slot = timeline.slots[s];
        if (slot && Number.isNaN(slot.committedAt)) {
          slot.committedAt = t;
          slot.via = 'aggregate';
          slot.origin = agg.origin;
          slot.aggKey = key;
        }
      }
    }
    return agg;
  };

  const sorted = [...rawEvents].sort((a, b) => a.t - b.t);
  let end = 0;
  for (const ev of sorted) {
    const node = ev.node;
    const t = num(ev.t, NaN);
    if (!valid(node) || !Number.isFinite(t)) continue;
    end = Math.max(end, t);
    const subnet = num(ev.subnet, -1);
    const timeline = l2[node];
    const slot = timeline && subnet >= 0 && subnet < subnets ? timeline.slots[subnet] : undefined;
    switch (ev.kind) {
      case 'transfer': {
        const to = ev.to;
        const arrival = num(ev.arrival, NaN);
        if (!valid(to) || !(arrival >= t)) break;
        const layer = (LAYERS as string[]).includes(String(ev.layer)) ? ev.layer as Layer : 'wasted';
        transfers.push({
          from: node, to, t, arrival, bytes: num(ev.bytes), layer,
          subnet: subnet === AGGREGATE_SUBNET ? -1 : subnet, prover: num(ev.prover, -1),
          committees: committeesOf(ev),
        });
        end = Math.max(end, arrival);
        break;
      }
      case 'proof_published': {
        publishTimes.push(t);
        const info = proverInfo(subnet, num(ev.prover));
        if (info) info.publishedAt = t;
        log(t, node, subnet, 'publish', `Published ${tag(ev)} (${kib(num(ev.bytes))})`);
        break;
      }
      case 'proof_committed':
        if (slot && Number.isNaN(slot.committedAt)) {
          slot.committedAt = t;
          slot.prover = num(ev.prover);
          slot.via = 'leaf';
        }
        log(t, node, subnet, 'commit', `Fetching ${tag(ev)} from ${nameOf(ev.from_node)}`);
        break;
      case 'proof_declined':
        if (slot) slot.declined += 1;
        log(t, node, subnet, 'decline', `Declined ${tag(ev)} — S${subnet} already chosen`);
        break;
      case 'chunk_received':
        if (slot && slot.via !== 'aggregate' && slot.prover === num(ev.prover, slot.prover)) {
          const held = num(ev.held);
          const last = slot.chunkSteps.at(-1);
          if (!last || held > last[1]) slot.chunkSteps.push([t, held]);
        }
        log(t, node, subnet, num(ev.added) > 0 ? 'chunk' : 'dup',
          `Chunks ${tag(ev)} from ${nameOf(ev.from_node)}: +${num(ev.added)} new, ${num(ev.dup)} dup (${num(ev.held)}/${chunkCount})`);
        break;
      case 'proof_received':
        if (slot) {
          if (ev.redundant) slot.redundant += 1;
          else if (Number.isNaN(slot.committedAt)) {
            slot.committedAt = t;
            slot.prover = num(ev.prover);
            slot.via = 'leaf';
          }
        }
        log(t, node, subnet, ev.redundant ? 'dup' : 'chunk', ev.redundant
          ? `Redundant ${tag(ev)} from ${nameOf(ev.from_node)} (S${subnet} already served)`
          : `Proof ${tag(ev)} from ${nameOf(ev.from_node)}`);
        break;
      case 'proof_complete':
        if (slot && Number.isNaN(slot.heldAt)) {
          slot.heldAt = t;
          slot.prover = num(ev.prover);
          slot.from = valid(ev.from_node) ? ev.from_node : -1;
          slot.via = 'leaf';
          if (Number.isNaN(slot.committedAt)) slot.committedAt = t;
          if (timeline && Number.isNaN(timeline.firstHeldAt)) timeline.firstHeldAt = t;
          subnetInfo[subnet].heldTimes.push(t);
          proverInfo(subnet, slot.prover)?.holdTimes.push(t);
        }
        log(t, node, subnet, 'held', `Holds ${tag(ev)} — ${num(ev.subnets_done)}/${subnets} subnets`);
        break;
      case 'all_subnets_complete':
        if (timeline) timeline.allSubnetsAt = t;
        log(t, node, -1, 'all', `All ${subnets} subnets held`);
        break;
      case 'aggregation_started': {
        const left = parseSubnetList(ev.left_subnets);
        const right = parseSubnetList(ev.right_subnets);
        const merge: Merge = {
          start: t, end: NaN, left, right, subnets: [...left, ...right].sort((a, b) => a - b),
          published: false, kept: true,
        };
        timeline?.merges.push(merge);
        pending[node].push(merge);
        log(t, node, -1, 'merge', `2→1 recursion started: {${left.join(',')}} + {${right.join(',')}}`);
        break;
      }
      case 'aggregation_done': {
        const subnetsDone = parseSubnetList(ev.subnets);
        const key = subnetsDone.join('-');
        const queue = pending[node];
        // Match by subnet set; fall back to the oldest running merge
        // (traces without subnet lists only carry sizes).
        let idx = queue.findIndex(m => m && m.subnets.join('-') === key);
        if (idx < 0) idx = queue.findIndex(m => m !== undefined);
        const kept = ev.kept !== false;
        if (idx >= 0) {
          queue[idx]!.end = t;
          queue[idx]!.kept = kept;
          queue[idx] = undefined;
        }
        log(t, node, -1, 'merge', kept
          ? `2→1 recursion done: aggregate covers ${num(ev.covered, subnetsDone.length)} subnets`
          : `2→1 recursion done but discarded: {${subnetsDone.join(',')}} was subsumed`);
        break;
      }
      case 'aggregate_complete':
        if (timeline) timeline.aggregatedAt = t;
        log(t, node, -1, 'aggregated', `Aggregate proof complete (${subnets} subnets)`);
        break;
      case 'intermediate_published': {
        const list = committeesOf(ev);
        const key = list.join('-');
        timeline?.published.push({ t, committees: list });
        const merge = timeline?.merges.filter(m => m.subnets.join('-') === key && m.end <= t).at(-1);
        if (merge) merge.published = true;
        log(t, node, -1, 'publish', `Published intermediate aggregate {${list.join(',')}}`, list);
        break;
      }
      case 'intermediate_committed': {
        const list = committeesOf(ev);
        if (timeline) fetchedAgg(timeline, ev, list, t);
        log(t, node, -1, 'commit',
          `Fetching aggregate ${aggTag(ev, list)} from ${nameOf(ev.from_node)}${ev.subsume ? ' (subsumes held items)' : ''}`, list);
        break;
      }
      case 'intermediate_declined':
        if (timeline) timeline.aggDeclined += 1;
        log(t, node, -1, 'decline', `Declined aggregate ${aggTag(ev, committeesOf(ev))} — overlaps what it holds`, committeesOf(ev));
        break;
      case 'intermediate_chunk_received': {
        const list = committeesOf(ev);
        if (timeline) {
          const key = list.join('-');
          const held = num(ev.held);
          for (const s of list) {
            const own = timeline.slots[s];
            if (!own || own.via !== 'aggregate' || own.aggKey !== key) continue;
            const last = own.chunkSteps.at(-1);
            if (!last || held > last[1]) own.chunkSteps.push([t, held]);
          }
        }
        log(t, node, -1, num(ev.added) > 0 ? 'chunk' : 'dup',
          `Chunks of aggregate {${list.join(',')}} from ${nameOf(ev.from_node)}: +${num(ev.added)} new, ${num(ev.dup)} dup (${num(ev.held)}/${chunkCount})`, list);
        break;
      }
      case 'intermediate_received': {
        const list = committeesOf(ev);
        if (timeline && ev.redundant) timeline.aggDeclined += 1;
        else if (timeline) fetchedAgg(timeline, ev, list, t);
        log(t, node, -1, ev.redundant ? 'dup' : 'chunk', ev.redundant
          ? `Redundant aggregate ${aggTag(ev, list)} from ${nameOf(ev.from_node)}`
          : `Aggregate ${aggTag(ev, list)} from ${nameOf(ev.from_node)}`, list);
        break;
      }
      case 'intermediate_complete': {
        const list = committeesOf(ev);
        if (timeline) {
          const agg = fetchedAgg(timeline, ev, list, t);
          agg.heldAt = t;
          agg.from = valid(ev.from_node) ? ev.from_node : -1;
          agg.saves = Math.max(0, parseSubnetList(ev.new).length - 1);
          timeline.mergesSaved += agg.saves;
          if (Number.isNaN(timeline.firstHeldAt)) timeline.firstHeldAt = t;
          for (const s of list) {
            const own = timeline.slots[s];
            if (!own || own.heldAt <= t) continue;
            own.heldAt = t;
            own.via = 'aggregate';
            own.origin = agg.origin;
            own.aggKey = agg.key;
            own.from = agg.from;
            own.prover = -1;
            if (Number.isNaN(own.committedAt)) own.committedAt = t;
            subnetInfo[s].heldTimes.push(t);
            subnetInfo[s].aggHoldTimes.push(t);
          }
        }
        log(t, node, -1, 'held', `Holds aggregate ${aggTag(ev, list)} — ${num(ev.subnets_done)}/${subnets} subnets`, list);
        break;
      }
      case 'item_dropped': {
        const list = parseSubnetList(ev.subnets);
        timeline?.dropped.push({ t, subnets: list });
        log(t, node, -1, 'decline', `Dropped held item {${list.join(',')}} — inside a fetched aggregate`, list);
        break;
      }
      default:
        break;
    }
  }

  transfers.sort((a, b) => a.t - b.t);
  let maxFlight = 0;
  const inbound: number[][] = nodes.map(() => []);
  transfers.forEach((tr, i) => {
    maxFlight = Math.max(maxFlight, tr.arrival - tr.t);
    inbound[tr.to].push(i);
    const timeline = l2[tr.to];
    if (!timeline) return;
    timeline.rxBytes += tr.bytes;
    const slot = tr.subnet >= 0 && tr.subnet < subnets ? timeline.slots[tr.subnet] : undefined;
    if (tr.layer === 'wasted') {
      timeline.wastedBytes += tr.bytes;
      if (slot) slot.wastedBytes += tr.bytes;
    } else if (slot && tr.layer !== 'announce') {
      slot.usefulBytes += tr.bytes;
    }
  });
  for (const list of inbound) list.sort((a, b) => transfers[a].arrival - transfers[b].arrival);

  const byArrival = transfers.map((_, i) => i).sort((a, b) => transfers[a].arrival - transfers[b].arrival);
  const arrivals = new Float64Array(byArrival.length);
  const rxCum = new Float64Array(byArrival.length);
  const wastedCum = new Float64Array(byArrival.length);
  let rx = 0;
  let wasted = 0;
  byArrival.forEach((ti, k) => {
    const tr = transfers[ti];
    rx += tr.bytes;
    if (tr.layer === 'wasted') wasted += tr.bytes;
    arrivals[k] = tr.arrival;
    rxCum[k] = rx;
    wastedCum[k] = wasted;
  });

  for (const info of subnetInfo) {
    info.heldTimes.sort((a, b) => a - b);
    info.aggHoldTimes.sort((a, b) => a - b);
    for (const p of info.provers) p.holdTimes.sort((a, b) => a - b);
  }
  const allSubnetsTimes = l2s.map(i => l2[i]!.allSubnetsAt).filter(Number.isFinite).sort((a, b) => a - b);
  const aggregatedTimes = l2s.map(i => l2[i]!.aggregatedAt).filter(Number.isFinite).sort((a, b) => a - b);

  const milestones: Milestone[] = [];
  if (publishTimes.length) {
    milestones.push({ t: Math.min(...publishTimes), label: 'First publish', kind: 'publish' });
    milestones.push({ t: Math.max(...publishTimes), label: 'Last publish', kind: 'publish' });
  }
  for (const [p, label] of [[0.5, 'p50'], [0.95, 'p95']] as const) {
    if (allSubnetsTimes.length) milestones.push({ t: percentile(allSubnetsTimes, p), label: `${label} all subnets`, kind: 'all' });
    if (aggregatedTimes.length) milestones.push({ t: percentile(aggregatedTimes, p), label: `${label} aggregated`, kind: 'aggregated' });
  }
  if (aggregatedTimes.length === l2s.length && aggregatedTimes.length) {
    milestones.push({ t: aggregatedTimes.at(-1)!, label: 'All aggregated', kind: 'aggregated' });
  }
  milestones.sort((a, b) => a.t - b.t);

  logs.sort((a, b) => a.t - b.t);
  const edges = (header.edges ?? [])
    .filter(e => valid(e.source) && valid(e.target))
    .map(e => ({ a: e.source, b: e.target, latencyUs: num(e.latency) }));

  return {
    title: String(meta.title || mode), mode, meta, subnets, provers, chunkCount,
    aggregationMs: num(meta.aggregation_ms, 290),
    intermediates: meta.intermediate_proofs === true
      || l2s.some(i => l2[i]!.published.length > 0 || l2[i]!.fetched.length > 0),
    nodes, l1s, l2s, l2, subnetInfo, transfers, maxFlight, inbound, edges, logs, milestones,
    allSubnetsTimes, aggregatedTimes, arrivals, rxCum, wastedCum, end,
  };
}
