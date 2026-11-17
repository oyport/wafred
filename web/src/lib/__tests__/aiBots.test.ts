import { describe, expect, it } from 'vitest'
import { withBlockedBotPolicy } from '@/lib/aiBots'
import type { AiBotPolicySetting } from '@/api/types'

describe('withBlockedBotPolicy', () => {
  it('appends a block override while keeping the other families', () => {
    const current: AiBotPolicySetting[] = [
      { bot_id: 'gptbot', action: 'allow' },
      { bot_id: 'claudebot', action: 'monitor' },
    ]
    expect(withBlockedBotPolicy(current, 'perplexitybot')).toEqual([
      { bot_id: 'gptbot', action: 'allow' },
      { bot_id: 'claudebot', action: 'monitor' },
      { bot_id: 'perplexitybot', action: 'block' },
    ])
  })

  it('replaces an existing override for the same family', () => {
    const current: AiBotPolicySetting[] = [
      { bot_id: 'gptbot', action: 'allow' },
      { bot_id: 'gptbot', action: 'monitor' },
    ]
    expect(withBlockedBotPolicy(current, 'gptbot')).toEqual([
      { bot_id: 'gptbot', action: 'block' },
    ])
  })

  it('works when the site has no overrides yet', () => {
    expect(withBlockedBotPolicy(undefined, 'gptbot')).toEqual([
      { bot_id: 'gptbot', action: 'block' },
    ])
  })
})
