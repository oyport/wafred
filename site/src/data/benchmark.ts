/**
 * Cross-vendor benchmark rows for the WAF test report page.
 *
 * WAFred figures come from the corrected 2026-11-22 full-corpus replay
 * (33 877 samples). PingWAF P13 rows are the prior version's final run on the
 * same nominal corpus, with earlier body framing. Other products are
 * historical values quoted from the blazehttp project README; they were not
 * retested in this run. Labels stay in English across locales; page copy
 * explains sources and denominator differences.
 */
export interface BenchRow {
  label: string;
  /** Percent, 0-100. */
  value: number;
  /** Current WAFred rows carry the site accent colour. */
  accent?: boolean;
}

export const INTERCEPTION_ROWS: BenchRow[] = [
  { label: "WAFred Strict+body", value: 96.05, accent: true },
  { label: "PingWAF prior P13 Strict+body", value: 93.8 },
  { label: "WAFred Strict", value: 76.14, accent: true },
  { label: "PingWAF prior P13 Strict", value: 76.0 },
  { label: "WAFred Normal+body", value: 75.08, accent: true },
  { label: "PingWAF prior P13 Normal+body", value: 71.9 },
  { label: "WAFred Normal", value: 60.33, accent: true },
  { label: "PingWAF prior P13 Normal", value: 60.2 },
  { label: "SafeLine strict", value: 76.17 },
  { label: "SafeLine balanced", value: 71.65 },
  { label: "ModSecurity PL4", value: 94.61 },
  { label: "ModSecurity PL1", value: 69.74 },
  { label: "Cloudflare free", value: 10.7 },
];

export const FALSE_POSITIVE_ROWS: BenchRow[] = [
  { label: "WAFred Strict+body", value: 0.057, accent: true },
  { label: "PingWAF prior P13 Strict+body", value: 0.063 },
  { label: "WAFred Strict", value: 0.012, accent: true },
  { label: "PingWAF prior P13 Strict", value: 0.015 },
  { label: "WAFred Normal+body", value: 0.036, accent: true },
  { label: "PingWAF prior P13 Normal+body", value: 0.042 },
  { label: "WAFred Normal", value: 0.012, accent: true },
  { label: "PingWAF prior P13 Normal", value: 0.015 },
  { label: "SafeLine strict", value: 0.22 },
  { label: "SafeLine balanced", value: 0.07 },
  { label: "ModSecurity PL4", value: 52.46 },
  { label: "ModSecurity PL1", value: 17.58 },
  { label: "Cloudflare free", value: 0.07 },
];

/** Scale ceilings, chosen so the longest bar sits just below the rail end. */
export const INTERCEPTION_MAX = 100;
export const FALSE_POSITIVE_MAX = 55;
