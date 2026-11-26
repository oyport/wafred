import { describe, expect, it } from 'vitest'
import { buildProbePoints, memoryTooltipValue } from './AgentProbePanel'
import type { HostSample } from '@/api/types'

function sample(overrides: Partial<HostSample> = {}): HostSample {
  return {
    id: 1,
    agent_id: 'agent-1',
    sampled_at: '2025-01-01T00:00:00Z',
    cpu_usage_percent: 12.5,
    load1: 1,
    load5: 2,
    load15: 3,
    memory_total_bytes: 8_589_934_592,
    memory_used_bytes: 4_294_967_296,
    memory_available_bytes: 4_294_967_296,
    process_rss_bytes: 65_536_000,
    swap_total_bytes: null,
    swap_used_bytes: null,
    disk_total_bytes: null,
    disk_used_bytes: null,
    net_rx_bytes: null,
    net_tx_bytes: null,
    disk_read_bytes: null,
    disk_write_bytes: null,
    process_count: null,
    tcp_connections: null,
    uptime_secs: null,
    created_at: '2025-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('buildProbePoints', () => {
  it('maps both series: host memory bytes and process RSS', () => {
    const points = buildProbePoints([sample()])
    expect(points).toHaveLength(1)
    expect(points[0].memoryUsed).toBe(4_294_967_296)
    expect(points[0].processRss).toBe(65_536_000)
  })

  it('keeps a null RSS as a gap (old agent that never reported)', () => {
    const points = buildProbePoints([
      sample({ process_rss_bytes: null }),
    ])
    expect(points[0].memoryUsed).toBe(4_294_967_296)
    expect(points[0].processRss).toBeNull()
  })

  it('preserves gaps when the field flips between null and a value', () => {
    const points = buildProbePoints([
      sample({ id: 1, sampled_at: '2025-01-01T00:00:00Z', process_rss_bytes: null }),
      sample({ id: 2, sampled_at: '2025-01-01T00:01:00Z', process_rss_bytes: 32_768 }),
      sample({ id: 3, sampled_at: '2025-01-01T00:02:00Z', process_rss_bytes: null }),
    ])
    expect(points.map((p) => p.processRss)).toEqual([null, 32_768, null])
  })
})

describe('memoryTooltipValue', () => {
  // recharts invokes formatter(value, name, ...): value first, name second.
  it('formats the RSS series as bytes, not as a percentage', () => {
    expect(memoryTooltipValue(65_536_000, 'processRss')).toBe('63 MB')
  })

  it('treats a null RSS tooltip value as 0 bytes', () => {
    expect(memoryTooltipValue(null, 'processRss')).toBe('0 B')
  })

  it('formats the host memory series as bytes too', () => {
    expect(memoryTooltipValue(4_294_967_296, 'memoryUsed')).toBe('4.0 GB')
  })

  it('renders a real value for BOTH series (no —, no absurd percentage)', () => {
    expect(memoryTooltipValue(4_294_967_296, 'memoryUsed')).not.toBe('—')
    expect(memoryTooltipValue(65_536_000, 'processRss')).not.toContain('%')
  })
})
