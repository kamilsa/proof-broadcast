// Side panels: overview, subnets, completion chart (left); aggregator matrix,
// node detail with the aggregation tree, and the event log (right).

import type { LogEntry, Model } from './model';
import { UI, proverColor, subnetColor } from './palette';
import { PHASE_COLOR, focusSubnet, type ViewState } from './render';
import {
  countUpTo, isMerging, l2Phase, mergesDone, networkCounts, slotState, subnetsHeld, type L2Phase,
} from './state';
import { drawTree } from './tree';

export interface PanelHooks {
  hoverSubnet(subnet: number): void;
  toggleSubnet(subnet: number): void;
  hoverNode(node: number): void;
  selectNode(node: number): void;
}

export const PHASE_LABEL: Record<L2Phase, string> = {
  idle: 'Idle',
  collecting: 'Collecting',
  all: 'All subnets held',
  aggregated: 'Aggregated',
};

export function fmtTime(us: number): string {
  if (!Number.isFinite(us)) return '—';
  return `${(us / 1e6).toFixed(3)} s`;
}

export function fmtBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KiB`;
  return `${bytes} B`;
}

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

function sizeCanvas(canvas: HTMLCanvasElement, width: number, height: number): CanvasRenderingContext2D {
  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
  }
  const ctx = canvas.getContext('2d')!;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return ctx;
}

type Tab = 'matrix' | 'detail' | 'log';

export class Panels {
  private model?: Model;
  private statValues = new Map<string, HTMLElement>();
  private subnetRows: Array<{ row: HTMLElement; pips: HTMLElement[]; bar: HTMLElement; segs: HTMLElement[]; count: HTMLElement }> = [];
  private matrixOrder: number[] = [];
  private matrixRowH = 10;
  private matrixTop = 22;
  private tab: Tab = 'matrix';
  private lastLogKey = '';
  private logTimes: number[] = [];

  constructor(private hooks: PanelHooks) {
    document.querySelectorAll<HTMLButtonElement>('#right-tabs button').forEach(btn => {
      btn.addEventListener('click', () => this.setTab(btn.dataset.tab as Tab));
    });
    const matrix = document.getElementById('matrix') as HTMLCanvasElement;
    matrix.addEventListener('mousemove', e => this.hooks.hoverNode(this.matrixNodeAt(e)));
    matrix.addEventListener('mouseleave', () => this.hooks.hoverNode(-1));
    matrix.addEventListener('click', e => {
      const node = this.matrixNodeAt(e);
      if (node >= 0) this.hooks.selectNode(node);
    });
  }

  setTab(tab: Tab): void {
    this.tab = tab;
    document.querySelectorAll<HTMLButtonElement>('#right-tabs button').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    for (const name of ['matrix', 'detail', 'log'] as Tab[]) {
      document.getElementById(`tab-${name}`)!.hidden = name !== tab;
    }
    this.lastLogKey = '';
  }

  setModel(model: Model): void {
    this.model = model;
    this.buildOverview();
    this.buildSubnets(model);
    this.matrixOrder = [...model.l2s].sort((a, b) => {
      const fa = model.l2[a]!.aggregatedAt;
      const fb = model.l2[b]!.aggregatedAt;
      return (Number.isFinite(fa) ? fa : Infinity) - (Number.isFinite(fb) ? fb : Infinity) || a - b;
    });
    this.logTimes = model.logs.map(entry => entry.t);
    this.lastLogKey = '';
  }

  // ── left: overview ──────────────────────────────────────────────────────

  private buildOverview(): void {
    const box = document.getElementById('overview')!;
    box.replaceChildren();
    this.statValues.clear();
    const group = (title: string, rows: Array<[string, string, string?]>) => {
      const g = el('div', 'stat-group');
      g.append(el('h3', undefined, title));
      for (const [key, label, color] of rows) {
        const row = el('div', 'stat-row');
        const name = el('span', 'label');
        if (color) {
          const dot = el('i', 'dot');
          dot.style.background = color;
          name.append(dot);
        }
        name.append(label);
        const value = el('span', 'value', '0');
        this.statValues.set(key, value);
        row.append(name, value);
        g.append(row);
      }
      box.append(g);
    };
    group('Provers', [
      ['l1', 'L1 published'],
      ['collecting', PHASE_LABEL.collecting, PHASE_COLOR.collecting],
      ['all', PHASE_LABEL.all, PHASE_COLOR.all],
      ['merging', '… running a merge', UI.aggregating],
      ['aggregated', PHASE_LABEL.aggregated, PHASE_COLOR.aggregated],
    ]);
    group('Traffic', [
      ['rx', 'Received'],
      ['wasted', 'Wasted', UI.wasted],
      ['flight', 'In flight'],
    ]);
  }

  private setStat(key: string, value: string): void {
    const node = this.statValues.get(key);
    if (node && node.textContent !== value) node.textContent = value;
  }

  // ── left: subnets ───────────────────────────────────────────────────────

  private buildSubnets(model: Model): void {
    const list = document.getElementById('subnet-list')!;
    list.replaceChildren();
    this.subnetRows = [];
    for (const info of model.subnetInfo) {
      const s = info.subnet;
      const row = el('div', 'subnet-row');
      const name = el('span', 'subnet-name', `S${String(s).padStart(2, '0')}`);
      name.style.color = subnetColor(s, model.subnets, 1, 0.8);
      const pipsBox = el('span', 'pips');
      const pips = info.provers.map(p => {
        const pip = el('i', 'pip');
        pip.title = `${model.nodes[p.node].name} — published ${fmtTime(p.publishedAt)}`;
        pip.style.borderColor = subnetColor(s, model.subnets, 0.6);
        pipsBox.append(pip);
        return pip;
      });
      const bar = el('span', 'cover');
      const segs = info.provers.map(p => {
        const seg = el('i');
        seg.style.background = proverColor(s, model.subnets, p.prover, model.provers);
        bar.append(seg);
        return seg;
      });
      const count = el('span', 'count', `0/${model.l2s.length}`);
      row.append(name, pipsBox, bar, count);
      row.addEventListener('mouseenter', () => this.hooks.hoverSubnet(s));
      row.addEventListener('mouseleave', () => this.hooks.hoverSubnet(-1));
      row.addEventListener('click', () => this.hooks.toggleSubnet(s));
      list.append(row);
      this.subnetRows.push({ row, pips, bar, segs, count });
    }
  }

  // ── per-frame / throttled updates ───────────────────────────────────────

  update(view: ViewState, inFlight: number): void {
    const model = this.model;
    if (!model) return;
    const t = view.t;
    const counts = networkCounts(model, t, inFlight);
    const l2n = model.l2s.length;
    this.setStat('l1', `${counts.l1Published}/${model.l1s.length}`);
    this.setStat('collecting', String(counts.collecting));
    this.setStat('merging', String(counts.merging));
    this.setStat('all', String(counts.all));
    this.setStat('aggregated', `${counts.aggregated}/${l2n}`);
    this.setStat('rx', fmtBytes(counts.rxBytes));
    const pct = counts.rxBytes ? ` (${Math.round((100 * counts.wastedBytes) / counts.rxBytes)}%)` : '';
    this.setStat('wasted', fmtBytes(counts.wastedBytes) + pct);
    this.setStat('flight', String(inFlight));

    const focus = focusSubnet(view);
    model.subnetInfo.forEach((info, s) => {
      const r = this.subnetRows[s];
      r.row.classList.toggle('focus', focus === s);
      r.row.classList.toggle('pinned', view.pinnedSubnet === s);
      r.row.classList.toggle('dim', focus >= 0 && focus !== s);
      let held = 0;
      info.provers.forEach((p, k) => {
        const published = p.publishedAt <= t;
        const fill = published ? proverColor(s, model.subnets, p.prover, model.provers) : 'transparent';
        if (r.pips[k].style.background !== fill) r.pips[k].style.background = fill;
        const holders = countUpTo(p.holdTimes, t);
        held += holders;
        r.segs[k].style.width = `${(100 * holders) / Math.max(1, l2n)}%`;
        r.segs[k].title = `p${p.prover}: chosen by ${holders} L2`;
      });
      const text = `${held}/${l2n}`;
      if (r.count.textContent !== text) r.count.textContent = text;
    });

    this.drawCompletion(model, t);
    if (this.tab === 'detail') this.renderDetail(model, view);
    if (this.tab === 'log') this.renderLog(model, view);
  }

  private drawCompletion(model: Model, t: number): void {
    const canvas = document.getElementById('completion') as HTMLCanvasElement;
    const width = canvas.parentElement!.clientWidth;
    const height = 120;
    const ctx = sizeCanvas(canvas, width, height);
    const left = 30;
    const right = 6;
    const top = 8;
    const bottom = height - 18;
    const end = Math.max(1, model.end);
    const x = (time: number) => left + (Math.min(time, end) / end) * (width - left - right);
    const y = (frac: number) => bottom - frac * (bottom - top);
    ctx.font = "10px 'Ubuntu Sans Mono', monospace";
    ctx.fillStyle = UI.text3;
    ctx.strokeStyle = UI.borderSubtle;
    ctx.lineWidth = 1;
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'right';
    for (const f of [0, 0.5, 1]) {
      ctx.beginPath();
      ctx.moveTo(left, y(f));
      ctx.lineTo(width - right, y(f));
      ctx.stroke();
      ctx.fillText(`${f * 100}%`, left - 4, y(f));
    }
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const stepS = end > 8e6 ? 2 : 1;
    for (let s = 0; s * 1e6 <= end; s += stepS) ctx.fillText(`${s}s`, x(s * 1e6), bottom + 4);
    const n = Math.max(1, model.l2s.length);
    const curve = (times: number[], color: string) => {
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      ctx.moveTo(x(0), y(0));
      times.forEach((time, k) => {
        ctx.lineTo(x(time), y(k / n));
        ctx.lineTo(x(time), y((k + 1) / n));
      });
      ctx.lineTo(x(end), y(times.length / n));
      ctx.stroke();
    };
    curve(model.allSubnetsTimes, UI.all);
    curve(model.aggregatedTimes, UI.aggregated);
    ctx.strokeStyle = UI.text2;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(x(t), top);
    ctx.lineTo(x(t), bottom);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // ── right: aggregator matrix ────────────────────────────────────────────

  private matrixNodeAt(e: MouseEvent): number {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    const row = Math.floor((e.clientY - rect.top - this.matrixTop) / this.matrixRowH);
    return row >= 0 && row < this.matrixOrder.length ? this.matrixOrder[row] : -1;
  }

  drawMatrix(view: ViewState): void {
    const model = this.model;
    if (!model || this.tab !== 'matrix') return;
    const canvas = document.getElementById('matrix') as HTMLCanvasElement;
    const box = canvas.parentElement!;
    const pad = parseFloat(getComputedStyle(box).paddingLeft) + parseFloat(getComputedStyle(box).paddingRight);
    const width = box.clientWidth - pad;
    const rows = this.matrixOrder.length;
    this.matrixRowH = Math.max(7, Math.min(13, Math.floor((box.clientHeight - this.matrixTop - 8) / Math.max(1, rows))));
    const height = this.matrixTop + rows * this.matrixRowH + 4;
    const ctx = sizeCanvas(canvas, width, height);
    const t = view.t;
    const nameW = 52;
    const tailW = 74;
    const cellW = (width - nameW - tailW) / model.subnets;
    const focus = focusSubnet(view);
    ctx.font = "10px 'Ubuntu Sans Mono', monospace";
    ctx.textBaseline = 'middle';
    // Header: subnet colour keys.
    for (let s = 0; s < model.subnets; s++) {
      ctx.fillStyle = subnetColor(s, model.subnets, focus >= 0 && focus !== s ? 0.25 : 1);
      ctx.fillRect(nameW + s * cellW + 1, 4, cellW - 2, 5);
      if (cellW >= 14 || s % 2 === 0) {
        ctx.fillStyle = UI.text3;
        ctx.textAlign = 'center';
        ctx.fillText(String(s), nameW + (s + 0.5) * cellW, 15);
      }
    }
    ctx.textAlign = 'left';
    ctx.fillStyle = UI.text3;
    ctx.fillText('merges', width - tailW + 4, 15);
    const mergesNeeded = Math.max(1, model.subnets - 1);
    this.matrixOrder.forEach((node, row) => {
      const tl = model.l2[node]!;
      const y0 = this.matrixTop + row * this.matrixRowH;
      const h = this.matrixRowH - 1.5;
      const highlighted = node === view.selectedNode || node === view.hoverNode;
      if (highlighted) {
        ctx.fillStyle = 'rgba(231,229,227,0.08)';
        ctx.fillRect(0, y0 - 0.5, width, this.matrixRowH);
      }
      ctx.fillStyle = highlighted ? UI.text : UI.text2;
      ctx.textAlign = 'left';
      ctx.fillText(model.nodes[node].name, 2, y0 + h / 2);
      for (let s = 0; s < model.subnets; s++) {
        const slot = tl.slots[s];
        const st = slotState(slot, t, model.chunkCount);
        const x = nameW + s * cellW + 0.5;
        const w = cellW - 1;
        const dim = focus >= 0 && focus !== s;
        ctx.fillStyle = 'rgba(68,64,60,0.45)';
        ctx.fillRect(x, y0, w, h);
        if (st.kind === 'held') {
          ctx.fillStyle = proverColor(s, model.subnets, slot.prover, model.provers, dim ? 0.3 : 1);
          ctx.fillRect(x, y0, w, h);
        } else if (st.kind === 'fetching') {
          ctx.fillStyle = subnetColor(s, model.subnets, dim ? 0.12 : 0.3);
          ctx.fillRect(x, y0, w, h);
          ctx.fillStyle = subnetColor(s, model.subnets, dim ? 0.3 : 0.9);
          ctx.fillRect(x, y0 + h * (1 - st.progress), w, h * st.progress);
        }
      }
      // Merge progress bar + phase dot.
      const phase = l2Phase(tl, t);
      const bx = width - tailW + 4;
      const bw = tailW - 20;
      ctx.fillStyle = 'rgba(68,64,60,0.45)';
      ctx.fillRect(bx, y0 + h * 0.25, bw, h * 0.5);
      ctx.fillStyle = phase === 'aggregated' ? UI.aggregated : UI.aggregating;
      if (isMerging(tl, t) && phase !== 'aggregated') {
        ctx.fillStyle = `oklch(0.84 0.15 85 / ${0.45 + 0.55 * (0.5 + 0.5 * Math.sin(view.clock / 140))})`;
      }
      ctx.fillRect(bx, y0 + h * 0.25, (bw * mergesDone(tl, t)) / mergesNeeded, h * 0.5);
      ctx.beginPath();
      ctx.arc(width - 8, y0 + h / 2, Math.min(3.5, h / 2), 0, Math.PI * 2);
      ctx.fillStyle = PHASE_COLOR[phase];
      ctx.fill();
    });
  }

  // ── right: detail ───────────────────────────────────────────────────────

  private renderDetail(model: Model, view: ViewState): void {
    const box = document.getElementById('tab-detail')!;
    const node = view.selectedNode >= 0 ? view.selectedNode : view.hoverNode;
    const key = `${node}`;
    if (box.dataset.node !== key) {
      box.dataset.node = key;
      box.replaceChildren();
      if (node < 0) {
        box.append(el('p', 'hint', 'Click an aggregator (L2) on the wheel or in the matrix to see how it collected and aggregated its proofs. Click an L1 prover or a subnet to follow one subnet.'));
        return;
      }
      const info = model.nodes[node];
      box.append(el('div', 'detail-title', info.name));
      box.append(el('div', 'detail-sub'));
      if (info.role === 'l2') {
        box.append(el('div', 'detail-stats'));
        const head = el('h3', undefined, 'Aggregation tree');
        box.append(head, el('p', 'hint small', 'Time runs down. Thin coloured line: fetching the subnet’s proof; dot: held; grey: waiting for a merge; gold bar: a 2→1 recursion.'));
        const canvas = el('canvas', 'tree');
        canvas.id = 'tree';
        box.append(canvas);
        box.append(el('h3', undefined, 'Subnets'));
        box.append(el('table', 'slots'));
      } else {
        box.append(el('div', 'detail-stats'));
      }
    }
    if (node < 0) return;
    const info = model.nodes[node];
    const t = view.t;
    const sub = box.querySelector('.detail-sub')!;
    const stats = box.querySelector('.detail-stats')!;
    if (info.role === 'l1') {
      const p = model.subnetInfo[info.subnet].provers.find(x => x.node === node)!;
      sub.textContent = `L1 prover · subnet ${info.subnet} · prover ${info.prover} · ${info.region}`;
      const sent = model.transfers.filter(tr => tr.from === node && tr.t <= t && tr.layer !== 'announce')
        .reduce((a, tr) => a + tr.bytes, 0);
      stats.innerHTML = '';
      stats.append(
        statLine('Published', fmtTime(p.publishedAt)),
        statLine('Chosen by', `${countUpTo(p.holdTimes, t)}/${model.l2s.length} L2`),
        statLine('Proof data sent', fmtBytes(sent)),
      );
      return;
    }
    const tl = model.l2[node]!;
    const phase = l2Phase(tl, t);
    sub.textContent = `L2 aggregator · ${info.region} · ${PHASE_LABEL[phase]}${isMerging(tl, t) ? ' · merging' : ''}`;
    stats.innerHTML = '';
    const rx = model.inbound[node].filter(i => model.transfers[i].arrival <= t);
    const rxBytes = rx.reduce((a, i) => a + model.transfers[i].bytes, 0);
    const wasted = rx.filter(i => model.transfers[i].layer === 'wasted').reduce((a, i) => a + model.transfers[i].bytes, 0);
    stats.append(
      statLine('Subnets held', `${subnetsHeld(tl, t)}/${model.subnets}`),
      statLine('2→1 merges', `${mergesDone(tl, t)}/${Math.max(1, model.subnets - 1)}`),
      statLine('All subnets at', fmtTime(tl.allSubnetsAt)),
      statLine('Aggregated at', fmtTime(tl.aggregatedAt)),
      statLine('Received', fmtBytes(rxBytes)),
      statLine('Wasted', `${fmtBytes(wasted)}${rxBytes ? ` (${Math.round((100 * wasted) / rxBytes)}%)` : ''}`),
    );
    const canvas = box.querySelector<HTMLCanvasElement>('#tree');
    if (canvas) {
      if (tl.merges.some(m => !m.subnets.length)) {
        canvas.replaceWith(el('p', 'hint', 'This trace predates per-merge subnet logging; re-run the simulation to see the tree.'));
      } else {
        drawTree(canvas, model, tl, t, box.clientWidth - 26, 280);
      }
    }
    const table = box.querySelector('table.slots')!;
    const wastedBySubnet = new Array<number>(model.subnets).fill(0);
    for (const i of rx) {
      const tr = model.transfers[i];
      if (tr.layer === 'wasted' && tr.subnet >= 0 && tr.subnet < model.subnets) wastedBySubnet[tr.subnet] += tr.bytes;
    }
    const declinedLabel = model.mode === 'partial' ? 'declined' : 'redundant';
    const rows: string[] = [`<tr><th>S</th><th>prover</th><th>from</th><th>held</th><th>wasted</th><th title="Other proofs of this subnet turned down (partial) or received anyway (gossipsub), whole run">${declinedLabel}</th></tr>`];
    tl.slots.forEach((slot, s) => {
      const st = slotState(slot, t, model.chunkCount);
      const chip = `<i class="chip" style="background:${subnetColor(s, model.subnets)}"></i>${s}`;
      const prover = st.kind === 'empty' ? '—'
        : `<i class="chip" style="background:${proverColor(s, model.subnets, slot.prover, model.provers)}"></i>p${slot.prover}`;
      const held = st.kind === 'held' ? fmtTime(slot.heldAt)
        : st.kind === 'fetching' ? `${Math.round(st.progress * 100)}%` : '—';
      const from = st.kind === 'held' && slot.from >= 0 ? model.nodes[slot.from].name : '';
      rows.push(`<tr class="${st.kind}"><td>${chip}</td><td>${prover}</td><td>${from}</td><td>${held}</td><td>${wastedBySubnet[s] ? fmtBytes(wastedBySubnet[s]) : ''}</td><td>${slot.declined + slot.redundant || ''}</td></tr>`);
    });
    table.innerHTML = rows.join('');
  }

  // ── right: log ──────────────────────────────────────────────────────────

  private renderLog(model: Model, view: ViewState): void {
    const node = view.selectedNode;
    const focus = focusSubnet(view);
    const upto = countUpTo(this.logTimes, view.t);
    const key = `${upto}|${node}|${focus}`;
    if (key === this.lastLogKey) return;
    this.lastLogKey = key;
    const list = document.getElementById('log-list')!;
    const header = document.getElementById('log-filter')!;
    header.textContent = node >= 0 ? `Filtered: ${model.nodes[node].name}`
      : focus >= 0 ? `Filtered: subnet ${focus}` : 'All nodes';
    const out: LogEntry[] = [];
    for (let i = upto - 1; i >= 0 && out.length < 250; i--) {
      const entry = model.logs[i];
      if (node >= 0 && entry.node !== node) continue;
      if (node < 0 && focus >= 0 && entry.subnet !== focus) continue;
      out.push(entry);
    }
    list.replaceChildren(...out.map(entry => {
      const row = el('div', `log-row ${entry.kind}`);
      const time = el('span', 'log-time', (entry.t / 1000).toFixed(1));
      const who = el('span', 'log-node', model.nodes[entry.node].name);
      who.addEventListener('click', () => this.hooks.selectNode(entry.node));
      const chip = el('i', 'chip');
      chip.style.background = entry.subnet >= 0 ? subnetColor(entry.subnet, model.subnets) : 'transparent';
      const text = el('span', 'log-text', entry.text);
      row.append(time, chip, who, text);
      return row;
    }));
  }
}

function statLine(label: string, value: string): HTMLElement {
  const row = el('div', 'stat-row');
  row.append(el('span', 'label', label), el('span', 'value', value));
  return row;
}
