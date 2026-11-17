import { describe, expect, it, vi } from 'vitest'

// `errorMessages` resolves copy through the shared i18n instance; a stub keeps
// these assertions about classification/mapping free of i18n bootstrapping.
vi.mock('@/i18n', () => ({
  default: {
    t: (key: string) =>
      ({
        'errors.invalidCredentials': 'Invalid email or password',
        'errors.domainConflict': 'This domain is already used',
        'errors.expressionInvalid': 'The expression is not valid',
      })[key] ?? key,
  },
}))

import { ApiError } from '@/api/client'
import {
  classifyFailure,
  failureReference,
  localizedErrorMessage,
  messageForErrorCode,
  retryDelayMs,
  serverRequestId,
} from '../errorMessages'

describe('failure classification (UX-10)', () => {
  const cases: [number, string][] = [
    [401, 'unauthorized'],
    [403, 'forbidden'],
    [404, 'not_found'],
    [409, 'conflict'],
    [422, 'validation'],
    [429, 'rate_limited'],
    [500, 'server_error'],
    [503, 'server_error'],
  ]

  it.each(cases)('maps HTTP %i to %s', (status, kind) => {
    expect(classifyFailure(new ApiError('x', status)).kind).toBe(kind)
  })

  it('distinguishes an offline request from a timeout', () => {
    expect(classifyFailure(new ApiError('offline', 0, 'network_error', true)).kind).toBe(
      'network',
    )
    expect(
      classifyFailure(new ApiError('request timed out', 0, 'network_error', true)).kind,
    ).toBe('timeout')
    expect(classifyFailure(new DOMException('aborted', 'AbortError')).kind).toBe(
      'timeout',
    )
    expect(classifyFailure(new TypeError('Failed to fetch')).kind).toBe('network')
    expect(classifyFailure('boom').kind).toBe('unknown')
  })

  it('exposes the docs slug and retryability of each kind', () => {
    const forbidden = classifyFailure(new ApiError('x', 403))
    expect(forbidden.docSlug).toBe('api')
    expect(forbidden.retryable).toBe(false)

    const server = classifyFailure(new ApiError('x', 503))
    expect(server.docSlug).toBe('deployment')
    expect(server.retryable).toBe(true)
  })
})

describe('retry backoff (UX-10)', () => {
  it('doubles from one second and caps at thirty', () => {
    expect(retryDelayMs(0)).toBe(1000)
    expect(retryDelayMs(1)).toBe(2000)
    expect(retryDelayMs(2)).toBe(4000)
    expect(retryDelayMs(3)).toBe(8000)
    expect(retryDelayMs(10)).toBe(30_000)
    expect(retryDelayMs(-1)).toBe(1000)
  })
})

describe('error code copy (UX-05)', () => {
  it('maps the namespaced codes and their legacy aliases', () => {
    expect(messageForErrorCode('auth.invalid_credentials')).toBe(
      'Invalid email or password',
    )
    expect(messageForErrorCode('domain_conflict')).toBe('This domain is already used')
    expect(messageForErrorCode('validation.expression_invalid')).toBe(
      'The expression is not valid',
    )
    expect(messageForErrorCode('unknown.code')).toBeNull()
    expect(messageForErrorCode(null)).toBeNull()
  })

  it('prefers localized copy, then the server message', () => {
    expect(
      localizedErrorMessage(
        new ApiError('invalid e-mail or password', 401, 'auth.invalid_credentials'),
      ),
    ).toBe('Invalid email or password')
    expect(localizedErrorMessage(new ApiError('boom', 500))).toBe('boom')
    expect(localizedErrorMessage(new Error('js failure'))).toBe('js failure')
    expect(localizedErrorMessage(null, 'fallback')).toBe('fallback')
  })
})

describe('request references (T03)', () => {
  it('quotes the server request id when the response carried one', () => {
    const err = new ApiError('boom', 500, 'internal_error', false, 'srv-req-42')
    expect(serverRequestId(err)).toBe('srv-req-42')
    expect(failureReference(err)).toBe('srv-req-42')
  })

  it('falls back to a short client reference without a server id', () => {
    const err = new ApiError('boom', 500)
    expect(serverRequestId(err)).toBeNull()
    const reference = failureReference(err)
    expect(reference).toMatch(/^[A-Z_]+-[A-Z0-9]+-[0-9A-Z]{2}$/)
    // Two failures never share the client fallback.
    expect(failureReference(err)).not.toBe(reference)
  })

  it('returns null for values that are not ApiErrors', () => {
    expect(serverRequestId(new Error('js'))).toBeNull()
    expect(serverRequestId(null)).toBeNull()
  })
})