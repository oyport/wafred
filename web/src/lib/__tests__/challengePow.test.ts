import { describe, expect, it } from 'vitest'
import {
  MAX_DIFFICULTY,
  MAX_LIMIT_PER_MIN,
  MIN_DIFFICULTY,
  validatePow,
} from '@/lib/challengePow'

const valid = {
  base_difficulty: 20,
  max_difficulty: 24,
  issue_limit_per_min: 120,
  verify_limit_per_min: 300,
}

describe('validatePow', () => {
  it('accepts the server defaults', () => {
    expect(validatePow(valid)).toBeNull()
  })

  it('accepts the documented bounds', () => {
    expect(
      validatePow({
        ...valid,
        base_difficulty: MIN_DIFFICULTY,
        max_difficulty: MAX_DIFFICULTY,
      }),
    ).toBeNull()
    expect(
      validatePow({
        ...valid,
        issue_limit_per_min: MAX_LIMIT_PER_MIN,
        verify_limit_per_min: 1,
      }),
    ).toBeNull()
  })

  it('rejects difficulties outside 4..28', () => {
    expect(validatePow({ ...valid, base_difficulty: 3 })).toBe('difficultyRange')
    expect(validatePow({ ...valid, max_difficulty: 29 })).toBe('difficultyRange')
    expect(validatePow({ ...valid, base_difficulty: Number.NaN })).toBe(
      'difficultyRange',
    )
  })

  it('rejects a max below the base', () => {
    expect(validatePow({ ...valid, base_difficulty: 24, max_difficulty: 20 })).toBe(
      'difficultyOrder',
    )
    // Equal values are fine: adaptive headroom is optional.
    expect(validatePow({ ...valid, base_difficulty: 22, max_difficulty: 22 })).toBeNull()
  })

  it('rejects non-positive or oversized limits', () => {
    expect(validatePow({ ...valid, issue_limit_per_min: 0 })).toBe('limitRange')
    expect(validatePow({ ...valid, verify_limit_per_min: 0 })).toBe('limitRange')
    expect(
      validatePow({ ...valid, verify_limit_per_min: MAX_LIMIT_PER_MIN + 1 }),
    ).toBe('limitRange')
  })
})