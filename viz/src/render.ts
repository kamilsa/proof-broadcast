// Canvas renderer for the subnet wheel.

import type { Model, Transfer } from './model';
import type { Layout } from './layout';
import { sectorAngles } from './layout';
import { UI, proverColor, subnetColor } from './palette';
import { countUpTo, isMerging, l2Phase, mergesDone, slotState, type L2Phase } from './state';

export type ColorMode = 'subnet' | 'outcome';

export interface ViewState {
  t: number;
  hoverNode: number;
  selectedNode: number;
  /** Subnet highlighted from the wheel, the subnet list or an L1 hover. */
  hoverSubnet: number;
  pinnedSubnet: number;
  colorMode: ColorMode;
  showAnnounce: boolean;
  showEdges: boolean;
  /** Wall-clock ms, drives pulsing only. */
  clock: number;
}

export const PHASE_COLOR: Record<L2Phase, string> = {
  idle: UI.idle,
  collecting: UI.collecting,
  all: UI.all,
  aggregated: UI.aggregated,
};

const FONT = "'Ubuntu Sans Mono', ui-monospace, monospace";

export function focusSubnet(view: ViewState): number {
  return view.pinnedSubnet >= 0 ? view.pinnedSubnet : view.hoverSubnet;
}

function transferColor(model: Model, tr: Transfer, mode: ColorMode, alpha: number): string {
  if (tr.layer === 'announce') return `oklch(0.62 0.02 260 / ${alpha * 0.55})`;
  if (mode === 'outcome') {
    if (tr.layer === 'wasted') return `oklch(0.70 0.18 35 / ${alpha})`;
    return `oklch(0.80 0.13 175 / ${alpha})`;
  }
  if (tr.subnet < 0) return `oklch(0.7 0 0 / ${alpha})`;
  return subnetColor(tr.subnet, model.subnets, tr.layer === 'wasted' ? alpha * 0.45 : alpha);
}

export class NetworkRenderer {
  private ctx: CanvasRenderingContext2D;
  private dpr = 1;
  private cssW = 0;
  private cssH = 0;

  constructor(private canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Canvas 2D unavailable');
    this.ctx = ctx;
  }

  resize(width: number, height: number): void {
    this.dpr = window.devicePixelRatio || 1;
    this.cssW = width;
    this.cssH = height;
    this.canvas.width = Math.round(width * this.dpr);
    this.canvas.height = Math.round(height * this.dpr);
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;
  }

  draw(model: Model, layout: Layout, view: ViewState, active: Transfer[]): void {
    const ctx = this.ctx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.cssW, this.cssH);
    const subnet = focusSubnet(view);
    const node = view.selectedNode >= 0 ? view.selectedNode : view.hoverNode;
    this.drawSectors(model, layout, view, subnet);
    if (view.showEdges || node >= 0) this.drawEdges(model, layout, view, node);
    this.drawTransfers(model, layout, view, active, subnet, node);
    this.drawL1s(model, layout, view, subnet);
    this.drawL2s(model, layout, view, subnet);
  }

  private drawSectors(model: Model, layout: Layout, view: ViewState, focus: number): void {
    const ctx = this.ctx;
    const { cx, cy, ringR, l1R } = layout;
    const holders = model.l2s.length || 1;
    ctx.lineCap = 'butt';
    for (const sector of layout.sectors) {
      const s = sector.subnet;
      const dim = focus >= 0 && focus !== s;
      const on = focus === s;
      // Sector band behind the L1 provers.
      ctx.beginPath();
      ctx.arc(cx, cy, ringR, sector.a0, sector.a1);
      ctx.strokeStyle = subnetColor(s, model.subnets, dim ? 0.03 : on ? 0.3 : 0.12);
      ctx.lineWidth = l1R * 3.4;
      ctx.stroke();
      // Coverage: share of L2s already holding this subnet.
      const held = countUpTo(model.subnetInfo[s].heldTimes, view.t) / holders;
      const inner = ringR - l1R * 2.4;
      ctx.beginPath();
      ctx.arc(cx, cy, inner, sector.a0, sector.a1);
      ctx.strokeStyle = subnetColor(s, model.subnets, dim ? 0.04 : 0.12);
      ctx.lineWidth = 3;
      ctx.stroke();
      if (held > 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, inner, sector.a0, sector.a0 + (sector.a1 - sector.a0) * held);
        ctx.strokeStyle = subnetColor(s, model.subnets, dim ? 0.2 : 0.95);
        ctx.stroke();
      }
      // Label outside the ring.
      const mid = (sector.a0 + sector.a1) / 2;
      const lr = ringR + l1R * 1.7 + 12;
      ctx.font = `${on ? 600 : 500} 11px ${FONT}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = subnetColor(s, model.subnets, dim ? 0.25 : 1, 0.8);
      ctx.fillText(`S${s}`, cx + lr * Math.cos(mid), cy + lr * Math.sin(mid));
    }
  }

  private drawEdges(model: Model, layout: Layout, view: ViewState, node: number): void {
    const ctx = this.ctx;
    ctx.lineWidth = 1;
    for (const e of model.edges) {
      const touches = e.a === node || e.b === node;
      if (!view.showEdges && !touches) continue;
      ctx.strokeStyle = touches ? 'rgba(231,229,227,0.22)' : 'rgba(168,162,158,0.045)';
      ctx.beginPath();
      ctx.moveTo(layout.x[e.a], layout.y[e.a]);
      ctx.lineTo(layout.x[e.b], layout.y[e.b]);
      ctx.stroke();
    }
  }

  private drawTransfers(
    model: Model, layout: Layout, view: ViewState, active: Transfer[], focus: number, node: number,
  ): void {
    const ctx = this.ctx;
    ctx.lineCap = 'round';
    for (const tr of active) {
      if (tr.layer === 'announce' && !view.showAnnounce) continue;
      const related = (focus < 0 || tr.subnet === focus) && (node < 0 || tr.from === node || tr.to === node);
      const focused = focus >= 0 || node >= 0;
      const alpha = related ? (focused ? 0.95 : 0.7) : 0.05;
      const x0 = layout.x[tr.from];
      const y0 = layout.y[tr.from];
      const x1 = layout.x[tr.to];
      const y1 = layout.y[tr.to];
      const p = Math.min(1, Math.max(0, (view.t - tr.t) / Math.max(1, tr.arrival - tr.t)));
      const hx = x0 + (x1 - x0) * p;
      const hy = y0 + (y1 - y0) * p;
      const len = Math.hypot(x1 - x0, y1 - y0) || 1;
      const trail = Math.min(tr.layer === 'announce' ? 6 : 22, len * p);
      const tx = hx - ((x1 - x0) / len) * trail;
      const ty = hy - ((y1 - y0) / len) * trail;
      const color = transferColor(model, tr, view.colorMode, alpha);
      ctx.strokeStyle = color;
      ctx.lineWidth = tr.layer === 'announce' ? 1 : tr.layer === 'wasted' ? 1.3 : focused ? 2.4 : 1.8;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(hx, hy);
      ctx.stroke();
      if (tr.layer === 'announce') continue;
      ctx.beginPath();
      ctx.arc(hx, hy, tr.layer === 'wasted' ? 1.8 : 2.6, 0, Math.PI * 2);
      ctx.fillStyle = tr.layer === 'wasted' && view.colorMode === 'subnet'
        ? `oklch(0.70 0.18 35 / ${alpha})`
        : color;
      ctx.fill();
    }
  }

  private drawL1s(model: Model, layout: Layout, view: ViewState, focus: number): void {
    const ctx = this.ctx;
    const holders = model.l2s.length || 1;
    for (const info of model.subnetInfo) {
      const dim = focus >= 0 && focus !== info.subnet;
      for (const p of info.provers) {
        const x = layout.x[p.node];
        const y = layout.y[p.node];
        const r = layout.r[p.node];
        const published = p.publishedAt <= view.t;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        if (published) {
          ctx.fillStyle = proverColor(info.subnet, model.subnets, p.prover, model.provers, dim ? 0.25 : 1);
          ctx.fill();
        } else {
          ctx.fillStyle = UI.bg;
          ctx.fill();
          ctx.strokeStyle = subnetColor(info.subnet, model.subnets, dim ? 0.15 : 0.55);
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }
        // How many L2s chose this prover's proof (gauge around the dot).
        const share = countUpTo(p.holdTimes, view.t) / holders;
        if (share > 0) {
          ctx.beginPath();
          ctx.arc(x, y, r + 3, -Math.PI / 2, -Math.PI / 2 + share * Math.PI * 2);
          ctx.strokeStyle = subnetColor(info.subnet, model.subnets, dim ? 0.2 : 0.9, 0.85);
          ctx.lineWidth = 2;
          ctx.stroke();
        }
        if (p.node === view.selectedNode || p.node === view.hoverNode) {
          ctx.beginPath();
          ctx.arc(x, y, r + 7, 0, Math.PI * 2);
          ctx.strokeStyle = p.node === view.selectedNode ? UI.text : UI.text2;
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }
      }
    }
  }

  private drawL2s(model: Model, layout: Layout, view: ViewState, focus: number): void {
    const ctx = this.ctx;
    const t = view.t;
    const pulse = 0.5 + 0.5 * Math.sin(view.clock / 140);
    const mergesNeeded = Math.max(1, model.subnets - 1);
    for (const i of model.l2s) {
      const tl = model.l2[i]!;
      const x = layout.x[i];
      const y = layout.y[i];
      const R = layout.r[i];
      const inner = R * 0.56;
      const phase = l2Phase(tl, t);
      const dimNode = view.selectedNode >= 0 && view.selectedNode !== i && view.hoverNode !== i;

      // Subnet segments, each pointing at its sector on the wheel.
      for (let s = 0; s < model.subnets; s++) {
        const [a0, a1] = sectorAngles(s, model.subnets);
        const st = slotState(tl.slots[s], t, model.chunkCount);
        const dim = dimNode || (focus >= 0 && focus !== s);
        ctx.beginPath();
        ctx.arc(x, y, R, a0, a1);
        ctx.arc(x, y, inner, a1, a0, true);
        ctx.closePath();
        if (st.kind === 'held') {
          ctx.fillStyle = proverColor(s, model.subnets, tl.slots[s].prover, model.provers, dim ? 0.18 : 1);
          ctx.fill();
        } else {
          ctx.fillStyle = st.kind === 'fetching'
            ? subnetColor(s, model.subnets, dim ? 0.05 : 0.2)
            : `rgba(68,64,60,${dim ? 0.25 : 0.55})`;
          ctx.fill();
          if (st.kind === 'fetching' && st.progress > 0) {
            const outer = inner + (R - inner) * st.progress;
            ctx.beginPath();
            ctx.arc(x, y, outer, a0, a1);
            ctx.arc(x, y, inner, a1, a0, true);
            ctx.closePath();
            ctx.fillStyle = subnetColor(s, model.subnets, dim ? 0.2 : 0.85);
            ctx.fill();
          }
        }
      }

      // Core: collection stage; a pulsing gold ring while a 2→1 recursion runs.
      const core = inner * 0.72;
      if (isMerging(tl, t) && phase !== 'aggregated') {
        ctx.beginPath();
        ctx.arc(x, y, core + 1.5 + pulse * 1.5, 0, Math.PI * 2);
        ctx.strokeStyle = `oklch(0.84 0.15 85 / ${dimNode ? 0.25 : 0.55 + 0.45 * pulse})`;
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(x, y, core, 0, Math.PI * 2);
      ctx.fillStyle = PHASE_COLOR[phase];
      ctx.globalAlpha = dimNode ? 0.3 : phase === 'idle' ? 0.6 : 1;
      ctx.fill();
      ctx.globalAlpha = 1;
      const done = mergesDone(tl, t);
      if (done > 0 && phase !== 'aggregated') {
        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.arc(x, y, core * 0.62, -Math.PI / 2, -Math.PI / 2 + (done / mergesNeeded) * Math.PI * 2);
        ctx.closePath();
        ctx.fillStyle = `oklch(0.84 0.15 85 / ${dimNode ? 0.3 : 0.9})`;
        ctx.fill();
      }
      if (phase === 'aggregated' && R >= 10) {
        ctx.strokeStyle = UI.bg;
        ctx.lineWidth = Math.max(1.5, core * 0.22);
        ctx.lineCap = 'round';
        ctx.beginPath();
        ctx.moveTo(x - core * 0.42, y + core * 0.02);
        ctx.lineTo(x - core * 0.1, y + core * 0.34);
        ctx.lineTo(x + core * 0.46, y - core * 0.3);
        ctx.stroke();
      }
      if (i === view.selectedNode || i === view.hoverNode) {
        ctx.beginPath();
        ctx.arc(x, y, R + 3.5, 0, Math.PI * 2);
        ctx.strokeStyle = i === view.selectedNode ? UI.text : UI.text2;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    }
  }
}
