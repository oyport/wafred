import { apiClient } from './client'
import type { Page, Tunnel, TunnelPairing, TunnelSettings } from './types'

/**
 * Tunnel connectors — `/api/v1/tunnels`.
 *
 * A tunnel is created here, not by the connector: creating one returns a
 * one-time pairing command that installs and pairs the connector in a single
 * step. The token in that command is shown exactly once; afterwards the console
 * can only mint a new one (`pairing`), which also rotates the credential.
 */
export const tunnelKeys = {
  all: ['tunnels'] as const,
  list: () => [...tunnelKeys.all, 'list'] as const,
  settings: () => [...tunnelKeys.all, 'settings'] as const,
}

export const tunnelsApi = {
  list: () => apiClient.get<Page<Tunnel>>('/tunnels', { query: { page_size: 200 } }),

  create: (data: { name: string; description?: string }) =>
    apiClient.post<TunnelPairing>('/tunnels', data),

  /** Rename, re-describe, or enable/disable (`status: 'active' | 'disabled'`). */
  update: (id: string, data: { name?: string; description?: string; status?: string }) =>
    apiClient.patch<Tunnel>(`/tunnels/${id}`, data),

  /**
   * Deletes the tunnel. `force` unbinds its origin pools first (they fall back
   * to direct origins) — the API refuses a bound tunnel without it, and the
   * console's confirmation dialog spells that consequence out.
   */
  remove: (id: string, force = false) =>
    apiClient.delete<void>(`/tunnels/${id}${force ? '?force=true' : ''}`),

  /** Mints a new pairing token and rotates the credential. */
  pairing: (id: string) => apiClient.post<TunnelPairing>(`/tunnels/${id}/pairing`, {}),

  /** Drops the credential; the connector must pair again to come back. */
  revoke: (id: string) => apiClient.post<Tunnel>(`/tunnels/${id}/revoke`, {}),

  settings: () => apiClient.get<TunnelSettings>('/settings/tunnel'),

  updateSettings: (data: Partial<TunnelSettings>) =>
    apiClient.put<TunnelSettings>('/settings/tunnel', data),
}