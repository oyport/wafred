/**
 * Client-side mirror of the server's adaptive proof-of-work validation
 * (`pingwaf-server/src/api/challenge.rs`). The server is authoritative; this
 * only keeps an out-of-range value from being submitted and explains why.
 *
 * The bounds are deliberately duplicated rather than fetched: the API returns
 * no schema, and a mismatch only ever means the form is stricter (the server
 * still rejects what it does not accept).
 */

/** Smallest accepted difficulty; below it the proof of work is decorative. */
export const MIN_DIFFICULTY = 4

/** Largest accepted difficulty; a browser must still finish the work. */
export const MAX_DIFFICULTY = 28

/** Bounds for the per-IP per-minute challenge/verify limits. */
export const MIN_LIMIT_PER_MIN = 1
export const MAX_LIMIT_PER_MIN = 1_000_000

/** The subset of the challenge config this validation looks at. */
export interface PowSettings {
  base_difficulty: number
  max_difficulty: number
  issue_limit_per_min: number
  verify_limit_per_min: number
}

/** i18n key suffixes under `pages.cc.pow_*`. */
export type PowIssue = 'difficultyRange' | 'difficultyOrder' | 'limitRange'

function inRange(value: number, min: number, max: number): boolean {
  return Number.isFinite(value) && value >= min && value <= max
}

/**
 * Returns the first problem with the settings, or `null` when they are valid.
 *
 * `max >= base` is checked as a pair: a max below the base would make the
 * adaptive step meaningless, which is exactly why the server validates them
 * together too.
 */
export function validatePow(settings: PowSettings): PowIssue | null {
  const { base_difficulty: base, max_difficulty: max } = settings
  if (
    !inRange(base, MIN_DIFFICULTY, MAX_DIFFICULTY) ||
    !inRange(max, MIN_DIFFICULTY, MAX_DIFFICULTY)
  ) {
    return 'difficultyRange'
  }
  if (max < base) return 'difficultyOrder'
  if (
    !inRange(settings.issue_limit_per_min, MIN_LIMIT_PER_MIN, MAX_LIMIT_PER_MIN) ||
    !inRange(settings.verify_limit_per_min, MIN_LIMIT_PER_MIN, MAX_LIMIT_PER_MIN)
  ) {
    return 'limitRange'
  }
  return null
}