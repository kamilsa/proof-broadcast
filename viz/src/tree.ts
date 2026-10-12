// Aggregation tree for one L2, drawn as a time dendrogram: time runs down,
// one column per subnet. A leaf column shows fetching (thin, subnet colour)
// then the held proof waiting in the pool (grey); each 2→1 recursion is a gold
// bar from its start to its end, joined to its two inputs by a bracket.

import type { L2Timeline, Merge, Model } from './model';
import { UI, proverColor, subnetColor } from './palette';

interface Item {
  key: string;
  subnets: number[];
  /** Leaf: held time. Aggregate: merge end. */
  readyAt: number;
  merge?: Merge;
  children: Item[];
  parent?: Item;
  x: number;
}

const keyOf = (subnets: number[]) => [...subnets].sort((a, b) => a - b).join('-');

export interface Tree {
  roots: Item[];
  leaves: Item[];
  /** Subnets not yet held by the end of the trace. */
  missing: number[];
}

export function buildTree(model: Model, tl: L2Timeline): Tree {
  const items = new Map<string, Item>();
  const leaf = (s: number): Item => {
    const key = String(s);
    let item = items.get(key);
    if (!item) {
      item = { key, subnets: [s], readyAt: tl.slots[s].heldAt, children: [], x: 0 };
      items.set(key, item);
    }
    return item;
  };
  for (let s = 0; s < model.subnets; s++) if (Number.isFinite(tl.slots[s].heldAt)) leaf(s);
  const merges = [...tl.merges].sort((a, b) => a.start - b.start);
  for (const merge of merges) {
    const pick = (subnets: number[]) => items.get(keyOf(subnets)) ?? (subnets.length === 1 ? leaf(subnets[0]) : undefined);
    const left = pick(merge.left);
    const right = pick(merge.right);
    const parent: Item = {
      key: keyOf(merge.subnets), subnets: merge.subnets, readyAt: merge.end, merge,
      children: [left, right].filter((c): c is Item => !!c), x: 0,
    };
    for (const child of parent.children) child.parent = parent;
    items.set(parent.key, parent);
  }
  const roots = [...items.values()].filter(item => !item.parent);
  const firstLeaf = (item: Item): number => item.children.length
    ? Math.min(...item.children.map(firstLeaf))
    : item.readyAt;
  roots.sort((a, b) => b.subnets.length - a.subnets.length || firstLeaf(a) - firstLeaf(b));
  const leaves: Item[] = [];
  const visit = (item: Item) => {
    if (!item.children.length) leaves.push(item);
    // Earlier-ready subtree on the left.
    [...item.children].sort((a, b) => firstLeaf(a) - firstLeaf(b)).forEach(visit);
  };
  roots.forEach(visit);
  const missing: number[] = [];
  for (let s = 0; s < model.subnets; s++) if (!Number.isFinite(tl.slots[s].heldAt)) missing.push(s);
  return { roots, leaves, missing };
}

function fmtMs(us: number): string {
  return `${(us / 1000).toFixed(0)}`;
}

export function drawTree(
  canvas: HTMLCanvasElement, model: Model, tl: L2Timeline, t: number, width: number, height: number,
): void {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d')!;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const font = "'Ubuntu Sans Mono', ui-monospace, monospace";

  const tree = buildTree(model, tl);
  const columns = tree.leaves.length + tree.missing.length;
  if (!columns) return;
  const left = 40;
  const right = 8;
  const top = 22;
  const bottom = height - 10;
  const colW = (width - left - right) / columns;
  tree.leaves.forEach((item, k) => { item.x = left + colW * (k + 0.5); });
  const place = (item: Item): number => {
    if (item.children.length) item.x = item.children.map(place).reduce((a, b) => a + b, 0) / item.children.length;
    return item.x;
  };
  tree.roots.forEach(place);

  const starts = tl.slots.map(s => s.committedAt).filter(Number.isFinite);
  const t0 = starts.length ? Math.min(...starts) : 0;
  const t1 = Math.max(t0 + 1, Number.isFinite(tl.aggregatedAt) ? tl.aggregatedAt : model.end);
  const y = (time: number) => top + ((Math.min(Math.max(time, t0), t1) - t0) / (t1 - t0)) * (bottom - top);

  // Time axis.
  ctx.font = `10px ${font}`;
  ctx.fillStyle = UI.text3;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  ctx.strokeStyle = UI.borderSubtle;
  ctx.lineWidth = 1;
  const ticks = 5;
  for (let k = 0; k <= ticks; k++) {
    const time = t0 + ((t1 - t0) * k) / ticks;
    const yy = y(time);
    ctx.fillText(fmtMs(time), left - 6, yy);
    ctx.beginPath();
    ctx.moveTo(left, yy);
    ctx.lineTo(width - right, yy);
    ctx.stroke();
  }
  ctx.save();
  ctx.translate(10, (top + bottom) / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = 'center';
  ctx.fillText('ms', 0, 0);
  ctx.restore();

  const drawAll = (ghost: boolean) => {
    const a = ghost ? 0.14 : 1;
    ctx.lineCap = 'butt';
    // Leaf columns: fetch (subnet colour), then held & waiting (grey).
    for (const item of tree.leaves) {
      const s = item.subnets[0];
      const slot = tl.slots[s];
      const x = item.x;
      if (Number.isFinite(slot.committedAt)) {
        ctx.strokeStyle = subnetColor(s, model.subnets, a * 0.8);
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(x, y(slot.committedAt));
        ctx.lineTo(x, y(slot.heldAt));
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(x, y(slot.heldAt), 3.5, 0, Math.PI * 2);
      ctx.fillStyle = proverColor(s, model.subnets, slot.prover, model.provers, a);
      ctx.fill();
    }
    const joins = (item: Item) => {
      for (const child of item.children) {
        const wait0 = child.readyAt;
        const wait1 = item.merge!.start;
        ctx.strokeStyle = `rgba(168,162,158,${0.55 * a})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(child.x, y(wait0));
        ctx.lineTo(child.x, y(wait1));
        ctx.lineTo(item.x, y(wait1));
        ctx.stroke();
        joins(child);
      }
      if (item.merge) {
        ctx.strokeStyle = `oklch(0.84 0.15 85 / ${a})`;
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.moveTo(item.x, y(item.merge.start));
        ctx.lineTo(item.x, y(Number.isFinite(item.merge.end) ? item.merge.end : t1));
        ctx.stroke();
      }
    };
    tree.roots.forEach(joins);
    if (Number.isFinite(tl.aggregatedAt)) {
      const root = tree.roots[0];
      ctx.beginPath();
      ctx.arc(root.x, y(tl.aggregatedAt), 5, 0, Math.PI * 2);
      ctx.fillStyle = `oklch(0.78 0.16 155 / ${a})`;
      ctx.fill();
    }
  };

  // Future faintly, then the past up to t at full strength.
  drawAll(true);
  const nowY = y(t);
  if (t >= t0) {
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, 0, width, nowY);
    ctx.clip();
    drawAll(false);
    ctx.restore();
  }
  if (t >= t0 && t <= t1) {
    ctx.strokeStyle = UI.text2;
    ctx.setLineDash([3, 3]);
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(left, nowY);
    ctx.lineTo(width - right, nowY);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Column labels.
  ctx.font = `10px ${font}`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'alphabetic';
  tree.leaves.forEach(item => {
    const s = item.subnets[0];
    ctx.fillStyle = subnetColor(s, model.subnets, 1, 0.8);
    ctx.fillText(String(s), item.x, top - 8);
  });
  tree.missing.forEach((s, k) => {
    const x = left + colW * (tree.leaves.length + k + 0.5);
    ctx.fillStyle = subnetColor(s, model.subnets, 0.4, 0.8);
    ctx.fillText(String(s), x, top - 8);
    ctx.strokeStyle = subnetColor(s, model.subnets, 0.3);
    ctx.setLineDash([2, 3]);
    ctx.beginPath();
    ctx.moveTo(x, top);
    ctx.lineTo(x, bottom);
    ctx.stroke();
    ctx.setLineDash([]);
  });
}
