import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

vi.hoisted(() => {
  const ls = globalThis.localStorage as unknown
  if (typeof ls !== 'object' || ls === null || typeof (ls as { getItem?: unknown }).getItem !== 'function') {
    ;(globalThis as Record<string, unknown>).localStorage = {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    }
  }
})

import type { Agent, Tunnel, TunnelPairing, TunnelSettings } from '@/api/types'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/**
 * Tunnel contract: a tunnel has three independent states (paired / enabled /
 * connected), the pairing command is one-time, and a pool's binding is
 * nullable. Collapsing any of those into a boolean would make the console lie
 * about a connector that is paired but offline, or about a pool that is
 * configured but has no live session.
 */
describe('tunnel API contract', () => {
  const TUNNEL: Tunnel = {
    id: '00000000-0000-0000-0000-000000000001',
    name: 'branch-office',
    description: null,
    status: 'active',
    paired: true,
    enabled: true,
    connector_online: false,
    connector_version: null,
    connector_hostname: null,
    last_seen_at: null,
    targets: ['10.0.0.5:8080'],
    // The blast radius of disabling the tunnel: the sites bound to it.
    sites: ['shop.example.com'],
    // Empty until an edge both binds its listener and gets an ingress address.
    ingress: [],
    sessions: [
      {
        agent_id: '00000000-0000-0000-0000-000000000002',
        agent_name: 'edge-1',
        agent_status: 'online',
        connected_at: '2026-11-25T01:00:00Z',
        last_seen_at: '2026-11-25T01:00:30Z',
        streams_active: 3,
        rtt_ms: 12,
        version: '0.32.50',
        hostname: 'connector-1',
      },
    ],
    created_at: '2026-11-25T00:00:00Z',
    updated_at: '2026-11-25T00:00:00Z',
  }

  it('keeps paired, enabled and connected as separate states', () => {
    expect(TUNNEL.paired).toBe(true)
    expect(TUNNEL.connector_online).toBe(false)
    // A paired tunnel with no connector is a real state the page must render.
    expect(TUNNEL.last_seen_at).toBeNull()
    expect(TUNNEL.connector_version).toBeNull()
    // A tunnel that no site uses yet is a real state the detail panel shows.
    expect(TUNNEL.sites).toEqual(['shop.example.com'])
    expect(TUNNEL.ingress).toEqual([])
  })

  it('carries the one-time pairing material alongside the tunnel', () => {
    const pairing: TunnelPairing = {
      tunnel: TUNNEL,
      pairing_token: 'ab'.repeat(32),
      pairing_command:
        'curl -fsSL https://example/install.sh | sudo bash -s -- --mode tunnel --server-url https://cp:9090 --token ab',
      expires_at: '2026-11-25T01:30:00Z',
    }
    expect(pairing.pairing_command).toContain('--mode tunnel')
    expect(pairing.expires_at).toBeTruthy()
  })

  it('types the global settings row', () => {
    const settings: TunnelSettings = {
      id: 1,
      enabled: true,
      pairing_ttl_seconds: 1800,
      max_streams_per_session: 256,
      max_targets_per_tunnel: 256,
      idle_timeout_seconds: 300,
      heartbeat_seconds: 20,
      session_token_ttl_seconds: 3600,
      updated_at: '2026-11-25T00:00:00Z',
    }
    expect(settings.enabled).toBe(true)
    // The token lifetime is what bounds a revoked tunnel on a partitioned
    // edge, so it is part of the contract the console shows.
    expect(settings.session_token_ttl_seconds).toBe(3600)
  })

  it('fetchTunnels hits /tunnels and the settings row hits /settings/tunnel', () => {
    const src = read('src/api/tunnels.ts')
    expect(src).toContain("apiClient.get<Page<Tunnel>>('/tunnels'")
    expect(src).toContain("apiClient.get<TunnelSettings>('/settings/tunnel'")
    expect(src).toContain("apiClient.put<TunnelSettings>('/settings/tunnel'")
    expect(src).toContain("apiClient.post<TunnelPairing>('/tunnels'")
    expect(src).toContain('`/tunnels/${id}/pairing`')
    expect(src).toContain('`/tunnels/${id}/revoke`')
  })

  it('an agent exposes its tunnel listener state and ingress address', () => {
    // Compile-time: the fields exist on the type. Runtime: the values are
    // independently nullable — a node without a listener reports null, and an
    // operator may set an ingress address before enabling the listener.
    const agent = {
      tunnel_ingress_addr: null,
      tunnel_listener_addr: null,
      tunnel_cert_sha256: null,
    } satisfies Pick<Agent, 'tunnel_ingress_addr' | 'tunnel_listener_addr' | 'tunnel_cert_sha256'>
    expect(agent.tunnel_ingress_addr).toBeNull()
    expect(agent.tunnel_listener_addr).toBeNull()
  })

  it('the one-time pairing dialog cannot be dismissed by accident', () => {
    const tab = read('src/pages/tunnels/TunnelsTab.tsx')
    // A stray overlay click or Esc must not destroy a token shown exactly once.
    expect(tab).toContain('dismissible={false}')
    const dialog = read('src/components/ui/Dialog.tsx')
    expect(dialog).toContain('dismissible?: boolean')
  })

  it('the pairing dialog explains the remaining steps and the detail panel names the blast radius', () => {
    const tab = read('src/pages/tunnels/TunnelsTab.tsx')
    // The first journey is three steps, not one: run the command, enable the
    // edge listener + ingress, bind an origin pool.
    expect(tab).toContain("t('pages.tunnels.checklistStep1')")
    expect(tab).toContain("t('pages.tunnels.checklistStep3')")
    // Disabling or deleting a tunnel must name the sites it affects.
    expect(tab).toContain("t('pages.tunnels.usedBy')")
    expect(tab).toContain('pendingDelete?.sites?.length')
  })

  it('a pool binding is nullable and the request accepts an empty string to clear it', () => {
    const src = read('src/api/types.ts')
    expect(src).toContain('tunnel_id: string | null')
    expect(src).toContain('/** Absent leaves the binding alone; an empty string clears it. */')
    const dialog = read('src/pages/sites/basic/PoolDialog.tsx')
    expect(dialog).toContain('tunnel_id: form.tunnelId')
  })
})