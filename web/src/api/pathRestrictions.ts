import { apiClient } from './client'
import type {
  CreatePathRestrictionRequest,
  PathRestriction,
  UpdatePathRestrictionRequest,
} from './types'

/** Path restrictions are independent of path exceptions and take precedence over them. */
export const pathRestrictionsApi = {
  list: (siteId: string) =>
    apiClient.get<PathRestriction[]>(`/sites/${siteId}/path-restrictions`),
  create: (siteId: string, data: CreatePathRestrictionRequest) =>
    apiClient.post<PathRestriction>(`/sites/${siteId}/path-restrictions`, data),
  update: (siteId: string, id: string, data: UpdatePathRestrictionRequest) =>
    apiClient.put<PathRestriction>(`/sites/${siteId}/path-restrictions/${id}`, data),
  remove: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/path-restrictions/${id}`),
}

export const pathRestrictionKeys = {
  all: (siteId: string) => ['sites', siteId, 'path-restrictions'] as const,
  list: (siteId: string) => [...pathRestrictionKeys.all(siteId), 'list'] as const,
}

export default pathRestrictionsApi
