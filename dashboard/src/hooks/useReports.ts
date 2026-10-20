import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { ReportOptions } from '@/types'

export function useReportOptions(enabled = true) {
  return useQuery<ReportOptions>({
    queryKey: ['report-options'],
    queryFn: () => api.get('/api/reports/options').then(r => r.data),
    enabled,
    staleTime: 60_000,
  })
}
