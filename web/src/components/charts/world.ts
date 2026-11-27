import { geoCentroid } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Feature, FeatureCollection } from 'geojson'
import worldTopoJson from 'world-atlas/countries-110m.json'
import { ISO_NUMERIC_TO_ALPHA2 } from './isoNumeric'

/**
 * The bundled world-atlas topology, parsed once and shared by every geographic
 * chart (the globe today). world-atlas ships ISO 3166-1 *numeric* feature ids;
 * the traffic stats use alpha-2 codes, so features are translated here.
 */
export const worldFeatures = feature(
  worldTopoJson as unknown as Parameters<typeof feature>[0],
  (worldTopoJson as unknown as { objects: { countries: never } }).objects
    .countries,
) as unknown as FeatureCollection

/**
 * Alpha-2 code → spherical centroid `[lon, lat]` for each country feature.
 * Used to place the request bubbles on the globe; features without a mapped
 * alpha-2 id (e.g. the `-99` "unknown" shapes) are skipped.
 */
export const COUNTRY_CENTROIDS: ReadonlyMap<string, [number, number]> = (() => {
  const centroids = new Map<string, [number, number]>()
  for (const f of worldFeatures.features as Feature[]) {
    const code = ISO_NUMERIC_TO_ALPHA2[String(f.id ?? '')]
    if (!code || centroids.has(code)) continue
    const [lon, lat] = geoCentroid(f)
    if (!Number.isFinite(lon) || !Number.isFinite(lat)) continue
    centroids.set(code, [lon, lat])
  }
  return centroids
})()