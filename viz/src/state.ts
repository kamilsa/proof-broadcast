// Per-frame queries against the precomputed model: "what does the network
// look like at time t". All cheap enough to run every animation frame.

import type { L2Timeline, Merge, Model, SubnetSlot, Transfer } from './model';

/** Number of entries in `sorted` that are <= t. */
export function countUpTo(sorted: ArrayLike<number>, t: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] <= t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

export type SlotKind = 'empty' | 'fetching' | 'held';

export interface SlotState {
  kind: SlotKind;
  /** 0..1 share of the chosen proof already held. */
  progress: number;
}

export function slotState(slot: SubnetSlot, t: number, chunkCount: number): SlotState {
  if (slot.heldAt <= t) return { kind: 'held', progress: 1 };
  if (!(slot.committedAt <= t)) return { kind: 'empty', progress: 0 };
  let held = 0;
  for (const [at, count] of slot.chunkSteps) {
    if (at > t) break;
    held = count;
  }
  return { kind: 'fetching', progress: Math.min(1, held / chunkCount) };
}

export type L2Phase = 'idle' | 'collecting' | 'all' | 'aggregated';

/** Collection stage. Merging overlaps with collecting (a 2→1 recursion starts
 * as soon as two proofs are held), so it is reported by `isMerging`. */
export function l2Phase(tl: L2Timeline, t: number): L2Phase {
  if (tl.aggregatedAt <= t) return 'aggregated';
  if (tl.allSubnetsAt <= t) return 'all';
  if (tl.firstHeldAt <= t || tl.slots.some(s => s.committedAt <= t)) return 'collecting';
  return 'idle';
}

export function isMerging(tl: L2Timeline, t: number): boolean {
  return tl.merges.some(m => m.start <= t && !(m.end <= t));
}

export function activeMerges(tl: L2Timeline, t: number): Merge[] {
  return tl.merges.filter(m => m.start <= t && !(m.end <= t));
}

/** Finished merges whose result was kept. */
export function mergesDone(tl: L2Timeline, t: number): number {
  let done = 0;
  for (const m of tl.merges) if (m.end <= t && m.kept) done += 1;
  return done;
}

/** Recursions the L2 needs, as known at t: subnets − 1, less those spared by
 * aggregates fetched from other L2s. */
export function mergesNeeded(model: Model, tl: L2Timeline, t: number): number {
  let saved = 0;
  for (const f of tl.fetched) if (f.heldAt <= t) saved += f.saves;
  return Math.max(1, model.subnets - 1 - saved);
}

export function aggregatesFetched(tl: L2Timeline, t: number): number {
  let n = 0;
  for (const f of tl.fetched) if (f.heldAt <= t) n += 1;
  return n;
}

export function aggregatesPublished(tl: L2Timeline, t: number): number {
  let n = 0;
  for (const p of tl.published) if (p.t <= t) n += 1;
  return n;
}

export function subnetsHeld(tl: L2Timeline, t: number): number {
  let held = 0;
  for (const s of tl.slots) if (s.heldAt <= t) held += 1;
  return held;
}

/** Transfers in flight at t (sent, not yet arrived). */
export function activeTransfers(model: Model, t: number, out: Transfer[] = []): Transfer[] {
  out.length = 0;
  const list = model.transfers;
  // Transfers are sorted by send time; anything sent before t - maxFlight
  // has certainly arrived.
  let lo = 0;
  let hi = list.length;
  const from = t - model.maxFlight;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid].t < from) lo = mid + 1;
    else hi = mid;
  }
  for (let i = lo; i < list.length && list[i].t <= t; i++) {
    if (list[i].arrival > t) out.push(list[i]);
  }
  return out;
}

export interface NetworkCounts {
  l1Published: number;
  idle: number;
  collecting: number;
  /** L2s running a 2→1 recursion right now (any stage). */
  merging: number;
  all: number;
  aggregated: number;
  rxBytes: number;
  wastedBytes: number;
  inFlight: number;
  /** Intermediate aggregates published / fetched (held) so far. */
  aggPublished: number;
  aggFetched: number;
}

export function networkCounts(model: Model, t: number, inFlight: number): NetworkCounts {
  const counts: NetworkCounts = {
    l1Published: 0, idle: 0, collecting: 0, merging: 0, all: 0, aggregated: 0,
    rxBytes: 0, wastedBytes: 0, inFlight, aggPublished: 0, aggFetched: 0,
  };
  for (const info of model.subnetInfo) {
    for (const p of info.provers) if (p.publishedAt <= t) counts.l1Published += 1;
  }
  for (const i of model.l2s) {
    const tl = model.l2[i]!;
    counts[l2Phase(tl, t)] += 1;
    if (isMerging(tl, t)) counts.merging += 1;
    counts.aggPublished += aggregatesPublished(tl, t);
    counts.aggFetched += aggregatesFetched(tl, t);
  }
  const k = countUpTo(model.arrivals, t);
  if (k > 0) {
    counts.rxBytes = model.rxCum[k - 1];
    counts.wastedBytes = model.wastedCum[k - 1];
  }
  return counts;
}
