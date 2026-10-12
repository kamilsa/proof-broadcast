import { parseTrace, type Model, type Transfer } from './model';
import { computeLayout, hitNode, hitSector, l2Order, type L2OrderKey, type Layout } from './layout';
import { NetworkRenderer, type ColorMode, type ViewState } from './render';
import { Panels, PHASE_LABEL, fmtBytes, fmtTime } from './panels';
import {
  activeTransfers, aggregatesFetched, aggregatesPublished, countUpTo, isMerging, l2Phase, mergesDone,
  mergesNeeded, subnetsHeld,
} from './state';
import { UI, subnetColor } from './palette';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const stage = $<HTMLElement>('stage');
const canvas = $<HTMLCanvasElement>('net');
const tooltip = $<HTMLElement>('tooltip');
const scrub = $<HTMLInputElement>('scrub');
const timeLabel = $<HTMLElement>('time');
const playBtn = $<HTMLButtonElement>('btn-play');
const speedSel = $<HTMLSelectElement>('speed');
const orderSel = $<HTMLSelectElement>('order-select');
const traceSel = $<HTMLSelectElement>('trace-select');

const renderer = new NetworkRenderer(canvas);
let model: Model | undefined;
let layout: Layout | undefined;
let playing = false;
let lastFrame = 0;
let lastPanelUpdate = 0;
let mouse: { x: number; y: number } | undefined;
const active: Transfer[] = [];

const view: ViewState = {
  t: 0, hoverNode: -1, selectedNode: -1, hoverSubnet: -1, pinnedSubnet: -1,
  colorMode: 'subnet', showAnnounce: false, showEdges: false, clock: 0,
};

const panels = new Panels({
  hoverSubnet: s => { view.hoverSubnet = s; dirty(); },
  toggleSubnet: s => { view.pinnedSubnet = view.pinnedSubnet === s ? -1 : s; dirty(); },
  hoverNode: n => { view.hoverNode = n; dirty(); },
  selectNode: n => select(n),
});

function dirty(): void {
  lastPanelUpdate = 0;
}

function select(node: number): void {
  view.selectedNode = node;
  if (node >= 0 && model) {
    const info = model.nodes[node];
    if (info.role === 'l1') view.pinnedSubnet = info.subnet;
    panels.setTab('detail');
  }
  dirty();
}

function relayout(): void {
  if (!model) return;
  const rect = stage.getBoundingClientRect();
  renderer.resize(rect.width, rect.height);
  // Keep the wheel clear of the timeline (below) and the legend (right).
  const usableH = rect.height - 90;
  const usableW = rect.width;
  layout = computeLayout(model, usableW, usableH, l2Order(model, orderSel.value as L2OrderKey));
  dirty();
}

function setTime(t: number): void {
  if (!model) return;
  view.t = Math.max(0, Math.min(model.end, t));
  scrub.value = String(Math.round(view.t));
  timeLabel.textContent = fmtTime(view.t);
  dirty();
}

function setPlaying(on: boolean): void {
  playing = on && !!model;
  if (playing && model && view.t >= model.end) setTime(0);
  playBtn.textContent = playing ? '❚❚' : '▶';
  playBtn.setAttribute('aria-label', playing ? 'Pause' : 'Play');
}

function renderParticleLegend(): void {
  const box = $<HTMLElement>('lg-particles');
  const rows: Array<[string, string]> = view.colorMode === 'subnet'
    ? [
      [`linear-gradient(90deg, ${[0, 3, 6, 9, 12].map(s => subnetColor(s, 16)).join(',')})`, 'proof data, coloured by subnet'],
      [UI.wasted, 'orange head: wasted (redundant / duplicate)'],
    ]
    : [
      ['oklch(0.80 0.13 175)', 'used (first proof / new chunks)'],
      [UI.wasted, 'wasted (redundant / duplicate)'],
    ];
  if (model?.intermediates && view.colorMode === 'subnet') {
    rows.push([UI.intermediate, 'big ivory head: intermediate aggregate (L2 → L2)']);
  }
  if (view.showAnnounce) rows.push([UI.announce, 'announce / request (metadata)']);
  box.replaceChildren(...rows.map(([color, label]) => {
    const row = document.createElement('div');
    row.className = 'lg-row';
    const line = document.createElement('i');
    line.className = 'lg-line';
    line.style.background = color;
    row.append(line, label);
    return row;
  }));
}

function renderLegendDonut(): void {
  const svg = $<HTMLElement>('lg-donut');
  const n = 16;
  const parts: string[] = [];
  for (let s = 0; s < n; s++) {
    const a0 = -Math.PI / 2 + (s * 2 * Math.PI) / n + 0.04;
    const a1 = -Math.PI / 2 + ((s + 1) * 2 * Math.PI) / n - 0.04;
    const held = s % 3 !== 2;
    const R = 11;
    const r = 6.5;
    const p = (rad: number, a: number) => `${(rad * Math.cos(a)).toFixed(2)} ${(rad * Math.sin(a)).toFixed(2)}`;
    parts.push(`<path d="M ${p(R, a0)} A ${R} ${R} 0 0 1 ${p(R, a1)} L ${p(r, a1)} A ${r} ${r} 0 0 0 ${p(r, a0)} Z" fill="${held ? subnetColor(s, n) : 'rgba(68,64,60,0.6)'}"/>`);
  }
  parts.push(`<circle r="4.5" fill="${UI.collecting}"/><circle r="5.6" fill="none" stroke="${UI.aggregating}" stroke-width="1.2"/>`);
  svg.innerHTML = parts.join('');
}

function tooltipHtml(node: number): string {
  if (!model) return '';
  const info = model.nodes[node];
  const t = view.t;
  if (info.role === 'l1') {
    const p = model.subnetInfo[info.subnet].provers.find(x => x.node === node)!;
    return `<b>${info.name}</b><br>L1 prover · subnet ${info.subnet} · p${info.prover} · ${info.region}`
      + `<br>published ${p.publishedAt <= t ? fmtTime(p.publishedAt) : 'not yet'}`
      + `<br>chosen by ${countUpTo(p.holdTimes, t)}/${model.l2s.length} L2`;
  }
  const tl = model.l2[node]!;
  const phase = l2Phase(tl, t);
  const aggs = model.intermediates
    ? `<br>aggregates: ${aggregatesPublished(tl, t)} published, ${aggregatesFetched(tl, t)} fetched`
    : '';
  return `<b>${info.name}</b><br>L2 aggregator · ${info.region}<br>${PHASE_LABEL[phase]}${isMerging(tl, t) ? ' · merging' : ''}`
    + ` · ${subnetsHeld(tl, t)}/${model.subnets} subnets · ${mergesDone(tl, t)}/${mergesNeeded(model, tl, t)} merges`
    + `<br>received ${fmtBytes(tl.rxBytes)} total, ${fmtBytes(tl.wastedBytes)} wasted${aggs}`;
}

function updateHover(): void {
  if (!model || !layout || !mouse) return;
  const node = hitNode(layout, mouse.x, mouse.y);
  view.hoverNode = node;
  view.hoverSubnet = node >= 0 && model.nodes[node].role === 'l1'
    ? model.nodes[node].subnet
    : node < 0 ? hitSector(layout, mouse.x, mouse.y) : -1;
  if (node >= 0) {
    tooltip.hidden = false;
    tooltip.innerHTML = tooltipHtml(node);
    const rect = stage.getBoundingClientRect();
    const left = Math.min(mouse.x + 14, rect.width - tooltip.offsetWidth - 8);
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${mouse.y + 14}px`;
  } else {
    tooltip.hidden = true;
  }
  canvas.style.cursor = node >= 0 || view.hoverSubnet >= 0 ? 'pointer' : 'default';
}

function frame(now: number): void {
  const dt = lastFrame ? now - lastFrame : 0;
  lastFrame = now;
  view.clock = now;
  if (model && layout) {
    if (playing) {
      setTime(view.t + dt * 1000 * Number(speedSel.value));
      if (view.t >= model.end) setPlaying(false);
    }
    if (mouse) updateHover();
    activeTransfers(model, view.t, active);
    renderer.draw(model, layout, view, active);
    panels.drawMatrix(view);
    if (now - lastPanelUpdate > 100) {
      lastPanelUpdate = now;
      panels.update(view, active.length);
    }
  }
  requestAnimationFrame(frame);
}

function loadModel(next: Model, name: string): void {
  model = next;
  view.selectedNode = -1;
  view.pinnedSubnet = -1;
  view.hoverNode = -1;
  view.hoverSubnet = -1;
  $<HTMLElement>('empty').hidden = true;
  $<HTMLElement>('run-title').textContent = `${next.title}`;
  const m = next.meta;
  $<HTMLElement>('run-meta').textContent = [
    next.mode,
    `${next.subnets} subnets × ${next.provers} L1`,
    `${next.l2s.length} L2`,
    m.proof_size_kib ? `${m.proof_size_kib} KiB proofs` : '',
    next.mode !== 'gossipsub' ? `${next.chunkCount} chunks` : '',
    m.chunked_send_idontwant ? 'IDONTWANT' : '',
    `2→1 ${next.aggregationMs} ms`,
    next.intermediates ? `intermediates${m.intermediate_fetch ? ` (${m.intermediate_fetch})` : ''}` : '',
    name,
  ].filter(Boolean).join(' · ');
  scrub.max = String(Math.ceil(next.end));
  $<HTMLElement>('ticks').replaceChildren(...next.milestones.map(ms => {
    const tick = document.createElement('i');
    tick.style.left = `${(100 * ms.t) / Math.max(1, next.end)}%`;
    tick.style.background = ms.kind === 'publish' ? subnetColor(10, 16) : ms.kind === 'all' ? UI.all : UI.aggregated;
    tick.title = `${ms.label} — ${fmtTime(ms.t)}`;
    return tick;
  }));
  panels.setModel(next);
  panels.setTab('matrix');
  renderParticleLegend();
  relayout();
  setTime(0);
  setPlaying(true);
}

async function loadText(text: string, name: string): Promise<void> {
  try {
    loadModel(parseTrace(text), name);
  } catch (err) {
    $<HTMLElement>('empty').hidden = false;
    $<HTMLElement>('empty').querySelector('p')!.textContent = `Could not load ${name}: ${(err as Error).message}`;
  }
}

async function loadUrl(url: string, name: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  await loadText(await res.text(), name);
}

// ── controls ─────────────────────────────────────────────────────────────

$<HTMLInputElement>('file-input').addEventListener('change', async e => {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (file) await loadText(await file.text(), file.name);
});
window.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('dragging'); });
window.addEventListener('dragleave', () => document.body.classList.remove('dragging'));
window.addEventListener('drop', async e => {
  e.preventDefault();
  document.body.classList.remove('dragging');
  const file = e.dataTransfer?.files?.[0];
  if (file) await loadText(await file.text(), file.name);
});
traceSel.addEventListener('change', () => {
  if (traceSel.value) {
    history.replaceState(null, '', `?trace=${encodeURIComponent(traceSel.value)}`);
    loadUrl(`/traces/${traceSel.value}`, traceSel.value).catch(console.error);
  }
});
playBtn.addEventListener('click', () => setPlaying(!playing));
$<HTMLButtonElement>('btn-reset').addEventListener('click', () => { setTime(0); });
scrub.addEventListener('input', () => { setPlaying(false); setTime(Number(scrub.value)); });
orderSel.addEventListener('change', relayout);
document.querySelectorAll<HTMLButtonElement>('#color-mode button').forEach(btn => {
  btn.addEventListener('click', () => {
    view.colorMode = btn.dataset.v as ColorMode;
    document.querySelectorAll('#color-mode button').forEach(b => b.classList.toggle('active', b === btn));
    renderParticleLegend();
  });
});
$<HTMLInputElement>('tgl-announce').addEventListener('change', e => {
  view.showAnnounce = (e.target as HTMLInputElement).checked;
  renderParticleLegend();
});
$<HTMLInputElement>('tgl-edges').addEventListener('change', e => {
  view.showEdges = (e.target as HTMLInputElement).checked;
});

canvas.addEventListener('mousemove', e => {
  const rect = canvas.getBoundingClientRect();
  mouse = { x: e.clientX - rect.left, y: e.clientY - rect.top };
});
canvas.addEventListener('mouseleave', () => {
  mouse = undefined;
  view.hoverNode = -1;
  view.hoverSubnet = -1;
  tooltip.hidden = true;
});
canvas.addEventListener('click', () => {
  if (!model || !layout || !mouse) return;
  const node = hitNode(layout, mouse.x, mouse.y);
  if (node >= 0) {
    select(node === view.selectedNode ? -1 : node);
    return;
  }
  const sector = hitSector(layout, mouse.x, mouse.y);
  if (sector >= 0) view.pinnedSubnet = view.pinnedSubnet === sector ? -1 : sector;
  else { view.selectedNode = -1; view.pinnedSubnet = -1; }
  dirty();
});
window.addEventListener('keydown', e => {
  if (!model || (e.target as HTMLElement).tagName === 'SELECT') return;
  if (e.key === ' ') { e.preventDefault(); setPlaying(!playing); }
  else if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    e.preventDefault();
    setPlaying(false);
    const step = (e.shiftKey ? 500 : 50) * 1000;
    setTime(view.t + (e.key === 'ArrowRight' ? step : -step));
  } else if (e.key === 'Home') setTime(0);
  else if (e.key === 'Escape') { view.selectedNode = -1; view.pinnedSubnet = -1; dirty(); }
});
new ResizeObserver(relayout).observe(stage);
const legendBtn = $<HTMLButtonElement>('legend-btn');
legendBtn.addEventListener('click', () => {
  const legend = $<HTMLElement>('legend');
  legend.hidden = !legend.hidden;
  legendBtn.setAttribute('aria-expanded', String(!legend.hidden));
});

renderParticleLegend();
renderLegendDonut();
requestAnimationFrame(frame);

// Dev server: list traces from ../shadow-output*/ and honour ?trace=.
(async () => {
  const wanted = new URLSearchParams(location.search).get('trace');
  try {
    const res = await fetch('/api/traces');
    if (res.ok) {
      const traces = (await res.json()) as Array<{ path: string; label: string }>;
      if (traces.length) {
        traceSel.hidden = false;
        traceSel.replaceChildren(new Option('Traces…', ''), ...traces.map(tr => new Option(tr.label, tr.path)));
        const initial = wanted ?? traces[0].path;
        traceSel.value = initial;
        await loadUrl(`/traces/${initial}`, initial);
        return;
      }
    }
  } catch {
    // Static build: no trace API.
  }
  if (wanted) await loadUrl(wanted, wanted).catch(console.error);
})();
