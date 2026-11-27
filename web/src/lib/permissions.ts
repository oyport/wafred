import type { User } from '@/api/types'

/** Demo accounts may browse administrator views; server-side policy stays read-only. */
export function hasAdminViewAccess(
  user: Pick<User, 'role' | 'is_demo'> | null | undefined,
): boolean {
  return user?.role === 'admin' || user?.is_demo === true
}
