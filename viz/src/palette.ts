// Colours. Subnets walk the hue wheel in order, so neighbouring sectors of the
// subnet wheel have neighbouring hues. Everything else stays neutral so the
// subnet colours carry the picture.

export const UI = {
  bg: '#0c0a09',
  panel: '#1c1917',
  border: '#44403c',
  borderSubtle: '#292524',
  text: '#e7e5e3',
  text2: '#a8a29e',
  text3: '#78716c',
  idle: '#57534e',
  collecting: 'oklch(0.72 0.05 250)',
  aggregating: 'oklch(0.84 0.15 85)',
  all: 'oklch(0.80 0.10 85)',
  aggregated: 'oklch(0.78 0.16 155)',
  wasted: 'oklch(0.70 0.18 35)',
  announce: 'oklch(0.60 0.02 260)',
  useful: 'oklch(0.78 0.14 175)',
  /** Intermediate aggregates exchanged between L2s. */
  intermediate: 'oklch(0.93 0.04 95)',
} as const;

export function intermediateColor(alpha = 1): string {
  return `oklch(0.93 0.04 95 / ${alpha})`;
}

/** A held subnet: the chosen prover's shade, or a darker shade of the subnet
 * when it arrived inside another L2's aggregate. */
export function heldColor(
  slot: { via: string; prover: number }, subnet: number, subnets: number, provers: number, alpha = 1,
): string {
  return slot.via === 'aggregate'
    ? subnetColor(subnet, subnets, alpha, 0.52)
    : proverColor(subnet, subnets, slot.prover, provers, alpha);
}

export function subnetHue(subnet: number, subnets: number): number {
  return (20 + (subnet * 360) / Math.max(1, subnets)) % 360;
}

export function subnetColor(subnet: number, subnets: number, alpha = 1, lightness = 0.74): string {
  const chroma = 0.15;
  return `oklch(${lightness} ${chroma} ${subnetHue(subnet, subnets).toFixed(1)} / ${alpha})`;
}

/** Slightly different lightness per prover, so the L2s' choices within one
 * subnet stay distinguishable while keeping the subnet hue. */
export function proverColor(subnet: number, subnets: number, prover: number, provers: number, alpha = 1): string {
  const span = provers > 1 ? prover / (provers - 1) : 0.5;
  return subnetColor(subnet, subnets, alpha, 0.86 - span * 0.26);
}
