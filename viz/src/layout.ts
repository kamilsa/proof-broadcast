// "Subnet wheel" layout: L1 provers on an outer ring split into one sector per
// subnet; L2 aggregators packed inside on a sunflower spiral, ordered so the
// first nodes in `l2Order` sit at the centre.

import type { Model } from './model';

export interface Sector {
  subnet: number;
  a0: number;
  a1: number;
}

export interface Layout {
  width: number;
  height: number;
  cx: number;
  cy: number;
  /** Radius of the L1 ring. */
  ringR: number;
  /** Radius of the disk holding the L2s. */
  innerR: number;
  x: Float64Array;
  y: Float64Array;
  /** Drawn radius per node. */
  r: Float64Array;
  sectors: Sector[];
  l1R: number;
  l2R: number;
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
const TOP = -Math.PI / 2;

export function sectorAngles(subnet: number, subnets: number): [number, number] {
  const step = (2 * Math.PI) / subnets;
  const gap = Math.min(step * 0.18, 0.08);
  return [TOP + subnet * step + gap / 2, TOP + (subnet + 1) * step - gap / 2];
}

export function computeLayout(model: Model, width: number, height: number, l2Order: number[]): Layout {
  const n = model.nodes.length;
  const x = new Float64Array(n);
  const y = new Float64Array(n);
  const r = new Float64Array(n);
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(60, Math.min(width, height) / 2 - 40);
  const ringR = radius * 0.9;
  const innerR = radius * 0.7;

  const sectors: Sector[] = [];
  const perSector = Math.max(1, model.provers);
  let l1R = 6;
  for (let s = 0; s < model.subnets; s++) {
    const [a0, a1] = sectorAngles(s, model.subnets);
    sectors.push({ subnet: s, a0, a1 });
    const slotArc = ((a1 - a0) * ringR) / perSector;
    l1R = Math.max(3, Math.min(9, slotArc * 0.34));
  }
  for (const i of model.l1s) {
    const node = model.nodes[i];
    const sector = sectors[node.subnet % model.subnets];
    const frac = (node.prover + 0.5) / perSector;
    const angle = sector.a0 + (sector.a1 - sector.a0) * frac;
    x[i] = cx + ringR * Math.cos(angle);
    y[i] = cy + ringR * Math.sin(angle);
    r[i] = l1R;
  }

  const count = l2Order.length;
  // Sunflower spacing is ~innerR * sqrt(pi / count); leave a gap between donuts.
  const l2R = count ? Math.max(4, Math.min(36, 0.47 * innerR * Math.sqrt(Math.PI / count))) : 10;
  const usable = Math.max(0, innerR - l2R);
  l2Order.forEach((node, k) => {
    const rad = count === 1 ? 0 : usable * Math.sqrt((k + 0.5) / count);
    const angle = k * GOLDEN_ANGLE + TOP;
    x[node] = cx + rad * Math.cos(angle);
    y[node] = cy + rad * Math.sin(angle);
    r[node] = l2R;
  });

  return { width, height, cx, cy, ringR, innerR, x, y, r, sectors, l1R, l2R };
}

export type L2OrderKey = 'finish' | 'region' | 'name';

/** L2 placement order: centre first. */
export function l2Order(model: Model, key: L2OrderKey): number[] {
  const nodes = [...model.l2s];
  const finish = (i: number) => {
    const tl = model.l2[i]!;
    return Number.isFinite(tl.aggregatedAt) ? tl.aggregatedAt : Number.POSITIVE_INFINITY;
  };
  if (key === 'finish') nodes.sort((a, b) => finish(a) - finish(b) || a - b);
  else if (key === 'region') {
    nodes.sort((a, b) => model.nodes[a].region.localeCompare(model.nodes[b].region) || finish(a) - finish(b));
  } else nodes.sort((a, b) => model.nodes[a].name.localeCompare(model.nodes[b].name));
  return nodes;
}

/** Node under (px, py), preferring the closest within its drawn radius. */
export function hitNode(layout: Layout, px: number, py: number, slack = 4): number {
  let best = -1;
  let bestD = Infinity;
  for (let i = 0; i < layout.x.length; i++) {
    const dx = layout.x[i] - px;
    const dy = layout.y[i] - py;
    const d = Math.hypot(dx, dy);
    if (d <= layout.r[i] + slack && d < bestD) {
      best = i;
      bestD = d;
    }
  }
  return best;
}

/** Subnet sector under (px, py) on the outer ring band, or −1. */
export function hitSector(layout: Layout, px: number, py: number): number {
  const d = Math.hypot(px - layout.cx, py - layout.cy);
  const band = layout.l1R * 3.2 + 14;
  if (Math.abs(d - layout.ringR) > band) return -1;
  let angle = Math.atan2(py - layout.cy, px - layout.cx);
  for (const s of layout.sectors) {
    while (angle < s.a0) angle += 2 * Math.PI;
    while (angle > s.a0 + 2 * Math.PI) angle -= 2 * Math.PI;
    if (angle >= s.a0 && angle <= s.a1) return s.subnet;
  }
  return -1;
}
