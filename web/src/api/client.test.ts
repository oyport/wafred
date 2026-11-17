import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, REQUEST_ID_HEADER, apiClient } from './client'

/**
 * T03: every `/api/v1` response carries `x-request-id`; the console keeps it on
 * the thrown `ApiError` so an error card can quote the exact request.
 */

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

const failureBody = {
  error: { code: 'internal_error', message: 'the control plane failed' },
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ApiError request id', () => {
  it('keeps the x-request-id header on a failed response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(500, failureBody, { [REQUEST_ID_HEADER]: 'srv-abc-123' }),
      ),
    )

    const err = await apiClient.get('/sites').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    const apiError = err as ApiError
    expect(apiError.status).toBe(500)
    expect(apiError.requestId).toBe('srv-abc-123')
  })

  it('leaves requestId null when the response carries no header', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(403, failureBody)))

    const err = await apiClient.get('/sites').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).requestId).toBeNull()
  })

  it('trims a padded header and treats a blank one as absent', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(400, failureBody, { [REQUEST_ID_HEADER]: '  id-1  ' }),
      ),
    )
    const err = await apiClient.get('/sites').catch((e: unknown) => e)
    expect((err as ApiError).requestId).toBe('id-1')

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(400, failureBody, { [REQUEST_ID_HEADER]: '   ' }),
      ),
    )
    const blank = await apiClient.get('/sites').catch((e: unknown) => e)
    expect((blank as ApiError).requestId).toBeNull()
  })

  it('does not invent a request id for a network failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )

    const err = await apiClient.get('/sites').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    const apiError = err as ApiError
    expect(apiError.networkError).toBe(true)
    expect(apiError.requestId).toBeNull()
  })
})