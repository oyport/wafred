import { COUNTRY_NAMES } from '@/api/geo'

/**
 * Country names in the UI language.
 *
 * The curated `COUNTRY_NAMES` table is English-only, so a zh/ja dashboard used
 * to show "United States" next to a translated page. `Intl.DisplayNames` is
 * built into the browser (no dependency, no bundle cost) and knows every ISO
 * 3166-1 region in every locale, so it is the primary source; the table stays
 * as the fallback for engines without it and for codes CLDR does not resolve
 * (`ZZ` renders as "unknown region" rather than as the code).
 */
const cache = new Map<string, Intl.DisplayNames | null>()

function displayNames(language: string): Intl.DisplayNames | null {
  const key = language || 'en'
  if (cache.has(key)) return cache.get(key) ?? null
  let names: Intl.DisplayNames | null = null
  try {
    names = new Intl.DisplayNames([key], { type: 'region', fallback: 'code' })
  } catch {
    // Engine without region display names: keep the English table fallback.
  }
  cache.set(key, names)
  return names
}

/** Localised region name, falling back to the English table then the code. */
export function countryName(code: string, language: string): string {
  const upper = (code ?? '').trim().toUpperCase()
  if (!upper) return '—'
  const english = COUNTRY_NAMES[upper]
  const names = displayNames(language)
  if (names) {
    try {
      const localised = names.of(upper)
      // `ZZ` is CLDR's "unknown region"; never print that for a real code.
      if (localised && localised !== upper && localised !== names.of('ZZ')) {
        return localised
      }
    } catch {
      // Codes outside the region grammar (`A1`, `EU`…): keep the fallback.
    }
  }
  return english ?? upper
}