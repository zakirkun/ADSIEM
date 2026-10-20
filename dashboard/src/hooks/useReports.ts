import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface ReportOptionCase {
  id: string
  title: string
  severity: string
  status: string
  created_at: string | null
}

export interface ReportOptionAgent {
  id: string
  hostname: string
  name: string
  status: string
}

export interface ReportOptions {
  cases: ReportOptionCase[]
  agents: ReportOptionAgent[]
}

export function useReportOptions(enabled = true) {
  return useQuery<ReportOptions>({
    queryKey: ['report-options'],
    queryFn: () => api.get('/api/reports/options').then(r => r.data),
    enabled,
    staleTime: 60_000,
  })
}
