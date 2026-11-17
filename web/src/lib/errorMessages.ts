import { useEffect, useState } from 'react'
import i18n from '@/i18n'
import { ApiError } from '@/api/client'

/**
 * Stable backend error codes → localized console copy (UX-05).
 *
 * The control plane returns a machine-readable `error.code` next to the
 * human-readable `error.message`. The message is written for operators reading
 * logs and stays English; the console maps the code to a translated message so
 * a zh/ja UI never shows a raw English sentence.
 *
 * Only codes that have a dedicated key here are translated. Everything else
 * keeps the server message, which is still the most specific description
 * available for one-off validation failures.
 */
const CODE_KEYS: Record<string, string> = {
  // Namespaced codes (v0.32.27+).
  'auth.invalid_credentials': 'errors.invalidCredentials',
  'site.domain_conflict': 'errors.domainConflict',
  'validation.expression_invalid': 'errors.expressionInvalid',
  // Un-namespaced aliases: older control planes and the pre-code strings that
  // some handlers still attach, so a mixed-version deployment degrades to the
  // same localized copy instead of English.
  invalid_credentials: 'errors.invalidCredentials',
  domain_conflict: 'errors.domainConflict',
  expression_invalid: 'errors.expressionInvalid',
}

/**
 * Localized message for a backend error code, or `null` when the code has no
 * mapping (caller falls back to the server message).
 */
export function messageForErrorCode(
  code: string | null | undefined,
): string | null {
  if (!code) return null
  const key = CODE_KEYS[code]
  if (!key) return null
  const value = i18n.t(key)
  return typeof value === 'string' && value !== key ? value : null
}

/**
 * Best message to show for a thrown value: the localized copy for a known
 * backend code, then the server/JS message, then the caller's fallback.
 */
export function localizedErrorMessage(
  err: unknown,
  fallback = '',
): string {
  if (err instanceof ApiError) {
    const localized = messageForErrorCode(err.code)
    if (localized) return localized
    return err.message || fallback
  }
  if (err instanceof Error) return err.message || fallback
  return fallback || String(err ?? '')
}

/**
 * True when `err` is the backend's "this domain is already used by another
 * site" failure. The code is authoritative; the message test keeps older
 * control planes (and the clone dialog's original heuristic) working.
 */
export function isDomainConflictError(err: unknown): boolean {
  if (err instanceof ApiError) {
    if (err.code === 'site.domain_conflict' || err.code === 'domain_conflict') {
      return true
    }
    return /already in use by another site|domain.*conflict/i.test(
      err.message || '',
    )
  }
  return false
}
/* ────────────────────────────────────────────────────────────────
   Failure classification (UX-10)
   ──────────────────────────────────────────────────────────────── */

/**
 * How a failed request should be presented. The console must tell an operator
 * *why* something failed — a 403 needs a permission fix, a 503 needs waiting,
 * a timeout needs a proxy check — so the raw HTTP status is folded into these
 * actionable kinds.
 */
export type FailureKind =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rate_limited'
  | 'conflict'
  | 'validation'
  | 'server_error'
  | 'network'
  | 'timeout'
  | 'unknown'

export interface FailureInfo {
  kind: FailureKind
  /** i18n key of the heading (`errors.<kind>Title`). */
  titleKey: string
  /** i18n key of the actionable hint (`errors.<kind>Hint`). */
  hintKey: string
  /** Docs slug (appended to {@link DOCS_BASE_URL}); `null` = no page. */
  docSlug: string | null
  /** Whether retrying the same request can plausibly succeed. */
  retryable: boolean
}

/** Public documentation base — the official site's `/docs` route. */
export const DOCS_BASE_URL = 'https://waf.red/docs'

/** Absolute documentation URL for a slug, or `null` when there is none. */
export function docsUrl(slug: string | null | undefined): string | null {
  return slug ? `${DOCS_BASE_URL}/${slug}` : null
}

/** True for aborted/timeout failures, which the API client reports as network errors. */
export function isTimeoutError(err: unknown): boolean {
  if (err instanceof ApiError) {
    if (err.code === 'timeout') return true
    if (!err.networkError) return false
  }
  if (err instanceof Error) {
    if (err.name === 'AbortError' || err.name === 'TimeoutError') return true
    return /time(d)?\s*out|timeout|aborted/i.test(err.message)
  }
  return false
}

const FAILURE_BY_STATUS: Record<number, FailureInfo> = {
  401: {
    kind: 'unauthorized',
    titleKey: 'errors.sessionExpiredTitle',
    hintKey: 'errors.sessionExpiredHint',
    docSlug: 'deployment',
    retryable: false,
  },
  403: {
    kind: 'forbidden',
    titleKey: 'errors.forbiddenTitle',
    hintKey: 'errors.forbiddenHint',
    docSlug: 'api',
    retryable: false,
  },
  404: {
    kind: 'not_found',
    titleKey: 'errors.notFoundTitle',
    hintKey: 'errors.notFoundHint',
    docSlug: 'api',
    retryable: false,
  },
  409: {
    kind: 'conflict',
    titleKey: 'errors.conflictTitle',
    hintKey: 'errors.conflictHint',
    docSlug: 'api',
    retryable: false,
  },
  422: {
    kind: 'validation',
    titleKey: 'errors.validationTitle',
    hintKey: 'errors.validationHint',
    docSlug: 'api',
    retryable: false,
  },
  429: {
    kind: 'rate_limited',
    titleKey: 'errors.rateLimitedTitle',
    hintKey: 'errors.rateLimitedHint',
    docSlug: 'deployment',
    retryable: true,
  },
}

/** Classifies any thrown value into an actionable failure kind (UX-10). */
export function classifyFailure(err: unknown): FailureInfo {
  if (err instanceof ApiError) {
    if (err.networkError || err.status === 0) {
      const timeout = isTimeoutError(err)
      return {
        kind: timeout ? 'timeout' : 'network',
        titleKey: timeout ? 'errors.timeoutTitle' : 'errors.networkTitle',
        hintKey: timeout ? 'errors.timeoutHint' : 'errors.networkHint',
        docSlug: 'deployment',
        retryable: true,
      }
    }
    const known = FAILURE_BY_STATUS[err.status]
    if (known) return known
    if (err.status >= 500) {
      return {
        kind: 'server_error',
        titleKey: 'errors.serverErrorTitle',
        hintKey: 'errors.serverErrorHint',
        docSlug: 'deployment',
        retryable: true,
      }
    }
    if (err.status === 400) {
      return {
        kind: 'validation',
        titleKey: 'errors.validationTitle',
        hintKey: 'errors.validationHint',
        docSlug: 'api',
        retryable: false,
      }
    }
  }
  if (isTimeoutError(err)) {
    return {
      kind: 'timeout',
      titleKey: 'errors.timeoutTitle',
      hintKey: 'errors.timeoutHint',
      docSlug: 'deployment',
      retryable: true,
    }
  }
  if (err instanceof TypeError) {
    return {
      kind: 'network',
      titleKey: 'errors.networkTitle',
      hintKey: 'errors.networkHint',
      docSlug: 'deployment',
      retryable: true,
    }
  }
  return {
    kind: 'unknown',
    titleKey: 'errors.unknownTitle',
    hintKey: 'errors.unknownHint',
    docSlug: null,
    retryable: false,
  }
}

/**
 * Exponential backoff for a manual retry: 1s, 2s, 4s, 8s, 16s, then capped at
 * 30s. Attempt is zero-based (`0` = first retry).
 */
export function retryDelayMs(attempt: number): number {
  const safe = Math.max(0, Math.floor(attempt))
  return Math.min(1000 * 2 ** safe, 30_000)
}

let referenceCounter = 0

/**
 * Correlation id the control plane returned for this failure (`x-request-id`,
 * T03). `null` when the request never reached the server or an older control
 * plane did not send the header.
 */
export function serverRequestId(err: unknown): string | null {
  return err instanceof ApiError ? err.requestId : null
}

/**
 * Reference an error card shows for a failure: the server's request id when
 * present (it matches the control plane's access log line), otherwise a short
 * client-minted value that an operator can quote in a bug report.
 *
 * Memoize the result per error instance before rendering — the client fallback
 * is intentionally unique per call so two failures never share a reference.
 */
export function failureReference(err: unknown): string {
  const server = serverRequestId(err)
  if (server) return server
  referenceCounter = (referenceCounter + 1) % 1296
  const stamp = Date.now().toString(36).toUpperCase()
  const suffix = referenceCounter.toString(36).toUpperCase().padStart(2, '0')
  const kind = classifyFailure(err).kind
  return `${kind.toUpperCase()}-${stamp}-${suffix}`
}

/**
 * Retry with exponential backoff for a page-level error card (UX-10).
 *
 * The first click retries immediately; after that the button stays disabled for
 * 1s, 2s, 4s … (capped at 30s) so a control plane that is already struggling is
 * not hammered by repeated clicks. The hook returns the remaining cooldown so
 * the card can say when the next attempt is allowed.
 */
export function useRetryBackoff(retry: () => void): {
  run: () => void
  waiting: boolean
  waitSeconds: number
} {
  const [attempt, setAttempt] = useState(0)
  const [waitSeconds, setWaitSeconds] = useState(0)
  const waiting = waitSeconds > 0

  useEffect(() => {
    if (!waiting) return
    const timer = window.setInterval(
      () => setWaitSeconds((seconds) => Math.max(0, seconds - 1)),
      1000,
    )
    return () => window.clearInterval(timer)
  }, [waiting])

  const run = () => {
    if (waiting) return
    setAttempt((value) => value + 1)
    setWaitSeconds(Math.ceil(retryDelayMs(attempt) / 1000))
    retry()
  }

  return { run, waiting, waitSeconds }
}
