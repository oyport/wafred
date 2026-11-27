import { apiClient } from './client'
import type { ChallengeConfig, UpdateChallengeRequest } from './types'

/**
 * CC protection / challenge — `/api/v1/sites/{siteId}/challenge`.
 *
 * A single per-site record: the master toggle, under-attack mode, the default
 * challenge level, clearance duration, the per-IP rate threshold, the path
 * exemptions, the adaptive proof-of-work range and the per-IP issuance /
 * verification limits. `GET` creates the row with defaults when absent.
 */
export const challengeApi = {
  get: (siteId: string) =>
    apiClient.get<ChallengeConfig>(`/sites/${siteId}/challenge`),

  update: (siteId: string, data: UpdateChallengeRequest) =>
    apiClient.put<ChallengeConfig>(`/sites/${siteId}/challenge`, data),
}

/** Sensible defaults matching the server-side `find_or_create` row. */
export function defaultChallengeConfig(): ChallengeConfig {
  return {
    enabled: false,
    under_attack_mode: false,
    default_level: 'non_interactive',
    clearance_duration_secs: 1800,
    rate_threshold: 100,
    exempt_paths: [],
    browser_integrity_check: true,
    tls_fingerprint_check: false,
    base_difficulty: 20,
    max_difficulty: 24,
    issue_limit_per_min: 120,
    verify_limit_per_min: 300,
  }
}

export const challengeKeys = {
  all: (siteId: string) => ['sites', siteId, 'challenge'] as const,
  config: (siteId: string) => ['sites', siteId, 'challenge', 'config'] as const,
}

export default challengeApi
