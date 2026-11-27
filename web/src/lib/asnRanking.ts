import type { TopAsn } from '@/api/types'

/** One row of the ASN ranking table. */
export interface AsnTrafficRow {
  /** AS number, always > 0 (unresolved rows are NULL server-side). */
  asn: number
  /** Organization name as returned by the API; may be empty on odd rows. */
  name: string
  requests: number
  /** Share of the denominator (0…1). */
  share: number
}

/**
 * The control plane's "no mapping" fallback is `Unknown (AS<number>)`
 * (`pingwaf_server::asn::display_name`). The UI localises it instead of showing
 * the English sentence in the middle of a translated table, so the pattern has
 * to be recognised here.
 */
const UNKNOWN_ASN_NAME = /^Unknown \(AS(\d+)\)$/i

/** True when the API's name is the fallback rather than a real organization. */
export function isUnknownAsnName(name: string | null | undefined): boolean {
  const trimmed = (name ?? '').trim()
  return trimmed === '' || UNKNOWN_ASN_NAME.test(trimmed)
}

/** `13335` → `AS13335`; the number is never rendered bare. */
export function formatAsn(asn: number): string {
  return `AS${asn}`
}

/**
 * Normalises the ASN ranking for the table.
 *
 * - drops rows without a usable AS number or a positive count (a defensive
 *   mirror of the server's own `top_asn` filter),
 * - folds duplicate AS numbers (the endpoint groups already; this keeps a
 *   concatenated/paged payload honest),
 * - sorts by requests descending with the AS number ascending as the
 *   deterministic tie-break — the same order the endpoint returns, so a
 *   re-render never reshuffles equal rows,
 * - computes the share against the window's total requests when the caller
 *   knows it, otherwise against the listed rows so the column still adds up.
 *
 * Addresses without a resolved ASN are excluded by the API, so the share can
 * legitimately sum to less than 100 % of the window.
 */
export function asnTrafficRows(
  rows: TopAsn[],
  totalRequests?: number,
): AsnTrafficRow[] {
  const merged = new Map<number, { asn: number; name: string; requests: number }>()
  for (const row of rows) {
    const asn = Math.trunc(Number(row.asn))
    const requests = Number(row.requests)
    if (!Number.isFinite(asn) || asn <= 0) continue
    if (!Number.isFinite(requests) || requests <= 0) continue
    const existing = merged.get(asn)
    if (existing) {
      existing.requests += requests
    } else {
      merged.set(asn, {
        asn,
        name: (row.asn_name ?? '').trim(),
        requests,
      })
    }
  }

  const listed = [...merged.values()]
  const denominator =
    totalRequests !== undefined && totalRequests > 0
      ? totalRequests
      : listed.reduce((sum, row) => sum + row.requests, 0)

  return listed
    .map((row) => ({
      ...row,
      share: denominator > 0 ? row.requests / denominator : 0,
    }))
    .sort((a, b) => b.requests - a.requests || a.asn - b.asn)
}