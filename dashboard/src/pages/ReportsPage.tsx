import { useMemo, useState } from 'react'
import { FileBarChart, Download, Loader2, Search } from 'lucide-react'
import { format, subDays } from 'date-fns'
import { api } from '@/api/client'
import { useReportOptions } from '@/hooks/useReports'
import SeverityBadge from '@/components/SeverityBadge'

const LANGUAGES = ['Indonesian', 'English', 'Spanish', 'French', 'German', 'Japanese']

type Scope = 'detailed' | 'cases' | 'agents'
type ReportFormat = 'pdf' | 'excel'

const SCOPES: { id: Scope; label: string; hint: string }[] = [
  {
    id: 'detailed',
    label: 'Laporan Detail Periode',
    hint: 'Kronologi penyerangan, rata-rata peringatan per hari, kategori, tingkat, dan alamat IP sumber.',
  },
  {
    id: 'cases',
    label: 'Laporan per Kasus',
    hint: 'Satu atau beberapa kasus sekaligus, lengkap dengan kronologi dan ringkasan investigasi.',
  },
  {
    id: 'agents',
    label: 'Laporan per Agen',
    hint: 'Satu agen secara detail, atau seluruh agen berperingkat menurut skor risiko.',
  },
]

export default function ReportsPage() {
  const [scope, setScope] = useState<Scope>('detailed')
  const [reportFormat, setReportFormat] = useState<ReportFormat>('pdf')
  const [dateFrom, setDateFrom] = useState(format(subDays(new Date(), 7), 'yyyy-MM-dd'))
  const [dateTo, setDateTo] = useState(format(new Date(), 'yyyy-MM-dd'))
  const [language, setLanguage] = useState('Indonesian')
  const [includeNarrative, setIncludeNarrative] = useState(true)
  const [caseIds, setCaseIds] = useState<string[]>([])
  const [agentIds, setAgentIds] = useState<string[]>([])
  const [caseSearch, setCaseSearch] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [error, setError] = useState('')

  const { data: options, isLoading: optionsLoading } = useReportOptions(scope !== 'detailed')

  const filteredCases = useMemo(() => {
    const all = options?.cases ?? []
    const q = caseSearch.trim().toLowerCase()
    return q ? all.filter(c => c.title.toLowerCase().includes(q)) : all
  }, [options?.cases, caseSearch])

  const toggle = (list: string[], setList: (v: string[]) => void, id: string) => {
    setList(list.includes(id) ? list.filter(x => x !== id) : [...list, id])
  }

  const handleGenerate = async () => {
    setError('')
    if (scope !== 'cases') {
      if (!dateFrom || !dateTo) { setError('Pilih rentang tanggal'); return }
      if (new Date(dateFrom) > new Date(dateTo)) {
        setError('Tanggal awal harus sebelum tanggal akhir'); return
      }
    }
    if (scope === 'cases' && caseIds.length === 0) {
      setError('Pilih minimal satu kasus'); return
    }

    setIsGenerating(true)
    let href: string | null = null
    try {
      const payload = {
        scope,
        date_from: scope === 'cases' ? null : dateFrom,
        date_to: scope === 'cases' ? null : dateTo,
        case_ids: scope === 'cases' ? caseIds : [],
        agent_ids: scope === 'agents' ? agentIds : [],
        format: reportFormat,
        include_narrative: includeNarrative,
        language,
      }
      const res = await api.post('/api/reports/build', payload, { responseType: 'blob' })

      const disposition = String(res.headers['content-disposition'] ?? '')
      const match = disposition.match(/filename="?([^";]+)"?/)
      const extension = reportFormat === 'excel' ? 'xlsx' : 'pdf'
      const fallback = `laporan-${scope}-${format(new Date(), 'yyyyMMdd')}.${extension}`

      href = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = href
      a.download = match?.[1] ?? fallback
      a.click()
    } catch (e) {
      const err = e as { response?: { data?: unknown } }
      let detail = 'Gagal membuat laporan'
      const data = err.response?.data
      if (data instanceof Blob) {
        try {
          const parsed = JSON.parse(await data.text()) as { detail?: string }
          if (parsed.detail) detail = parsed.detail
        } catch {
          detail = 'Gagal membuat laporan'
        }
      } else if (data && typeof data === 'object' && 'detail' in data) {
        detail = String((data as { detail: unknown }).detail)
      }
      setError(detail)
    } finally {
      if (href) URL.revokeObjectURL(href)
      setIsGenerating(false)
    }
  }

  const activeScope = SCOPES.find(s => s.id === scope)!

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <FileBarChart size={20} />
        <h1 className="text-xl font-bold">Laporan</h1>
      </div>

      <div className="rounded-lg border border-border bg-card p-5 space-y-5 max-w-3xl">
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide mb-3">
            Jenis Laporan
          </h2>
          <div className="grid gap-2 sm:grid-cols-3">
            {SCOPES.map(s => (
              <button
                key={s.id}
                type="button"
                onClick={() => setScope(s.id)}
                className={`text-left rounded border px-3 py-2 text-sm transition ${
                  scope === s.id
                    ? 'border-primary bg-primary/10 font-medium'
                    : 'border-border hover:bg-muted'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
          <p className="text-xs text-muted-foreground mt-2">{activeScope.hint}</p>
        </div>

        {scope !== 'cases' && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Dari tanggal</label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Sampai tanggal</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>
        )}

        {scope === 'cases' && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-muted-foreground">
                Pilih kasus ({caseIds.length} dipilih, maksimum 50)
              </label>
              {caseIds.length > 0 && (
                <button
                  type="button"
                  onClick={() => setCaseIds([])}
                  className="text-xs text-muted-foreground hover:text-foreground"
                >
                  Bersihkan pilihan
                </button>
              )}
            </div>
            <div className="relative mb-2">
              <Search size={14} className="absolute left-2 top-2.5 text-muted-foreground" />
              <input
                value={caseSearch}
                onChange={(e) => setCaseSearch(e.target.value)}
                placeholder="Cari judul kasus"
                className="w-full bg-muted border border-border rounded pl-7 pr-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div className="max-h-64 overflow-y-auto rounded border border-border divide-y divide-border">
              {optionsLoading && (
                <p className="px-3 py-2 text-xs text-muted-foreground">Memuat kasus…</p>
              )}
              {!optionsLoading && filteredCases.length === 0 && (
                <p className="px-3 py-2 text-xs text-muted-foreground">Tidak ada kasus yang cocok.</p>
              )}
              {filteredCases.map(c => (
                <label
                  key={c.id}
                  className="flex items-center gap-3 px-3 py-2 text-sm cursor-pointer hover:bg-muted"
                >
                  <input
                    type="checkbox"
                    checked={caseIds.includes(c.id)}
                    onChange={() => toggle(caseIds, setCaseIds, c.id)}
                  />
                  <span className="flex-1 truncate">{c.title}</span>
                  <SeverityBadge severity={c.severity} />
                </label>
              ))}
            </div>
          </div>
        )}

        {scope === 'agents' && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-muted-foreground">
                {agentIds.length === 0
                  ? 'Seluruh agen (berperingkat menurut risiko)'
                  : `${agentIds.length} agen dipilih`}
              </label>
              {agentIds.length > 0 && (
                <button
                  type="button"
                  onClick={() => setAgentIds([])}
                  className="text-xs text-muted-foreground hover:text-foreground"
                >
                  Kembali ke seluruh agen
                </button>
              )}
            </div>
            <div className="max-h-56 overflow-y-auto rounded border border-border divide-y divide-border">
              {optionsLoading && (
                <p className="px-3 py-2 text-xs text-muted-foreground">Memuat agen…</p>
              )}
              {!optionsLoading && (options?.agents.length ?? 0) === 0 && (
                <p className="px-3 py-2 text-xs text-muted-foreground">Belum ada agen terdaftar.</p>
              )}
              {(options?.agents ?? []).map(a => (
                <label
                  key={a.id}
                  className="flex items-center gap-3 px-3 py-2 text-sm cursor-pointer hover:bg-muted"
                >
                  <input
                    type="checkbox"
                    checked={agentIds.includes(a.id)}
                    onChange={() => toggle(agentIds, setAgentIds, a.id)}
                  />
                  <span className="flex-1 truncate">{a.hostname}</span>
                  <span className="text-xs text-muted-foreground">{a.status}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Format berkas</label>
            <select
              value={reportFormat}
              onChange={(e) => setReportFormat(e.target.value as ReportFormat)}
              className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="pdf">PDF — untuk pimpinan dan arsip</option>
              <option value="excel">Excel — untuk analisis dan penyaringan data</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Bahasa ringkasan</label>
            <input
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              list="report-languages"
              className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <datalist id="report-languages">
              {LANGUAGES.map(l => <option key={l} value={l} />)}
            </datalist>
          </div>
        </div>

        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          <input
            type="checkbox"
            checked={includeNarrative}
            onChange={(e) => setIncludeNarrative(e.target.checked)}
          />
          Sertakan ringkasan naratif AI (memerlukan 9router yang aktif)
        </label>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <button
          onClick={handleGenerate}
          disabled={isGenerating}
          className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
        >
          {isGenerating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
          {isGenerating ? 'Menyusun laporan…' : 'Unduh laporan'}
        </button>
      </div>
    </div>
  )
}
