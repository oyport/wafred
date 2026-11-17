import type { AiBotPolicySetting } from '@/api/types'

/**
 * Applies a "block this bot" override to an AI-crawl policy list.
 *
 * The server replaces the whole list when `policies` is present, so the caller
 * must send every family it wants to keep; this helper replaces an existing
 * override for the same bot and leaves the others untouched.
 */
export function withBlockedBotPolicy(
  policies: AiBotPolicySetting[] | undefined,
  botId: string,
): AiBotPolicySetting[] {
  return [
    ...(policies ?? []).filter((policy) => policy.bot_id !== botId),
    { bot_id: botId, action: 'block' },
  ]
}
