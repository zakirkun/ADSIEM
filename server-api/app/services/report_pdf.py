# server-api/app/services/report_pdf.py
"""Renders a ReportDataset to PDF. Pure: no DB, no network, no LLM."""
import io

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from app.services.report_data import (
    SEVERITY_ORDER, ReportDataset, label_category, label_severity, label_status,
)

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#64748b"),
}

_INK = colors.HexColor("#1e293b")
_MUTED = colors.HexColor("#64748b")
_RULE = colors.HexColor("#e2e8f0")

GLOSSARY = [
    ("Peringatan (alert)",
     "Pemberitahuan otomatis bahwa sebuah aturan deteksi menemukan kejadian mencurigakan pada log."),
    ("Kasus (case)",
     "Kumpulan peringatan yang berasal dari satu rangkaian serangan yang sama."),
    ("Tingkat keparahan (severity)",
     "Bobot risiko sebuah peringatan, dari Informasi (paling ringan) sampai Kritis (paling berat)."),
    ("Kategori serangan (kill chain stage)",
     "Tahapan serangan menurut kerangka MITRE ATT&CK, misalnya akses awal, eksekusi, atau pengeluaran data."),
    ("Alamat IP sumber (source IP)",
     "Alamat asal koneksi yang memicu peringatan. Untuk serangan dari internet, ini alamat penyerang."),
    ("MITRE ATT&CK",
     "Katalog taktik dan teknik serangan yang dipakai industri untuk menamai perilaku penyerang."),
    ("Agen (agent)",
     "Perangkat lunak yang dipasang di server atau komputer untuk mengirim log ke platform ini."),
    ("Positif palsu (false positive)",
     "Peringatan yang setelah diperiksa ternyata bukan serangan."),
    ("IOC (Indikator Kompromi)",
     "Petunjuk yang menandakan serangan, misalnya alamat IP, nama domain, atau sidik jari berkas."),
    ("Rata-rata peringatan per hari",
     "Jumlah peringatan dibagi jumlah hari dalam periode laporan, untuk melihat lonjakan volume."),
]


def _styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=19, leading=23, textColor=_INK, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, leading=16, spaceBefore=14,
                             spaceAfter=7, textColor=_INK),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=10.5, leading=14, spaceBefore=9,
                             spaceAfter=4, textColor=_INK),
        "meta": ParagraphStyle("meta", parent=base["Normal"], fontSize=8.5, leading=12, textColor=_MUTED),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9.5, leading=14, alignment=TA_LEFT,
                               textColor=_INK),
        "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8, leading=11, textColor=_MUTED),
        "cell": ParagraphStyle("cell", parent=base["Normal"], fontSize=8, leading=10.5, textColor=_INK),
        "cellb": ParagraphStyle("cellb", parent=base["Normal"], fontSize=8, leading=10.5,
                                textColor=colors.white, fontName="Helvetica-Bold"),
    }


def _esc(text) -> str:
    return (str(text)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _css(color) -> str:
    return "#" + color.hexval()[2:]


def _table(rows, widths, styles, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    cmds = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]
    if header:
        cmds += [
            ("BACKGROUND", (0, 0), (-1, 0), _INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(cmds))
    return t


def _kv_table(pairs, styles):
    rows = [[Paragraph(_esc(k), styles["cell"]), Paragraph(_esc(v), styles["cell"])] for k, v in pairs]
    t = Table(rows, colWidths=[5.2 * cm, 11.8 * cm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, _RULE),
        ("TEXTCOLOR", (0, 0), (0, -1), _MUTED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _severity_bar(counts: dict, styles):
    total = sum(counts.values()) or 1
    rows = [[Paragraph("<b>Tingkat</b>", styles["cellb"]),
             Paragraph("<b>Jumlah</b>", styles["cellb"]),
             Paragraph("<b>Porsi</b>", styles["cellb"])]]
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        share = f"{n / total * 100:.1f}%"
        rows.append([
            Paragraph(f'<font color="{_css(_SEVERITY_COLORS[sev])}"><b>{label_severity(sev)}</b></font>',
                      styles["cell"]),
            Paragraph(str(n), styles["cell"]),
            Paragraph(share, styles["cell"]),
        ])
    if len(rows) == 1:
        return Paragraph("Tidak ada peringatan pada periode ini.", styles["body"])
    return _table(rows, [6 * cm, 3 * cm, 3 * cm], styles)


def _timeline_flow(entries, styles, limit=120):
    if not entries:
        return [Paragraph("Tidak ada kejadian tercatat.", styles["body"])]
    flow = []
    for entry in entries[:limit]:
        stamp = entry.occurred_at.strftime("%d/%m/%Y %H:%M UTC")
        sev = label_severity(entry.severity) if entry.severity else ""
        head = f'<font color="#64748b">{stamp}</font> &nbsp; <b>{_esc(entry.title)}</b>'
        if sev:
            color = _css(_SEVERITY_COLORS.get((entry.severity or "info").lower(), _MUTED))
            head += f' &nbsp;<font color="{color}" size="7">[{_esc(sev)}]</font>'
        if entry.source_ip:
            head += f' &nbsp;<font size="7" color="#64748b">IP {_esc(entry.source_ip)}</font>'
        if entry.hostname:
            head += f' &nbsp;<font size="7" color="#64748b">Host {_esc(entry.hostname)}</font>'
        if entry.actor:
            head += f' &nbsp;<font size="7" color="#64748b">{_esc(entry.actor)}</font>'
        flow.append(Paragraph(head, styles["body"]))
        if entry.detail:
            flow.append(Paragraph(f'<font size="7.5" color="#475569">{_esc(entry.detail)}</font>', styles["body"]))
        flow.append(Spacer(1, 4))
    if len(entries) > limit:
        flow.append(Paragraph(
            f"<i>Diringkas: {len(entries) - limit} kejadian berikutnya tersedia pada berkas Excel.</i>",
            styles["small"]))
    return flow


def _narrative_blocks(text, styles):
    out = []
    for para in (text or "").split("\n\n"):
        if para.strip():
            out.append(Paragraph(_esc(para.strip()).replace("\n", "<br/>"), styles["body"]))
            out.append(Spacer(1, 5))
    return out


def _header(ds: ReportDataset, styles, subtitle: str):
    story = [Paragraph(_esc(ds.org_name or "Laporan Keamanan"), styles["h1"]),
             Paragraph(_esc(ds.title), styles["meta"])]
    if subtitle:
        story.append(Paragraph(_esc(subtitle), styles["meta"]))
    story.append(Paragraph(
        f"Dibuat: {ds.generated_at.strftime('%d %B %Y, %H:%M UTC')}", styles["meta"]))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", color=_RULE))
    story.append(Spacer(1, 4))
    return story


def _executive_summary(ds, styles):
    story = [Paragraph("Ringkasan untuk Pimpinan", styles["h2"])]
    if ds.narrative:
        story.extend(_narrative_blocks(ds.narrative, styles))
    else:
        story.append(Paragraph(
            "Ringkasan naratif tidak tersedia karena layanan bahasa tidak dikonfigurasi. "
            "Angka pada bagian berikut tetap lengkap dan dapat digunakan.", styles["small"]))
    return story


def _key_numbers(ds, styles):
    pairs = [
        ("Cakupan laporan", ds.subject_label or "-"),
        ("Jumlah peringatan (alert)", f"{ds.total_alerts}"),
        ("Rata-rata peringatan per hari", f"{ds.avg_alerts_per_day}"),
        ("Jumlah kasus (case)", f"{ds.total_cases}"),
    ]
    if ds.busiest_day:
        pairs.append(("Hari tersibuk", f"{ds.busiest_day[0]} ({ds.busiest_day[1]} peringatan)"))
    if ds.period_from and ds.period_to:
        pairs.append(("Periode", f"{ds.period_from.isoformat()} s.d. {ds.period_to.isoformat()}"))
    return [Paragraph("Angka Utama", styles["h2"]), _kv_table(pairs, styles)]


def _category_section(ds, styles):
    if not ds.category_counts:
        return []
    rows = [[Paragraph("<b>Kategori serangan</b>", styles["cellb"]),
             Paragraph("<b>Jumlah</b>", styles["cellb"])]]
    for cat, n in sorted(ds.category_counts.items(), key=lambda kv: kv[1], reverse=True):
        rows.append([Paragraph(_esc(label_category(cat)), styles["cell"]),
                     Paragraph(str(n), styles["cell"])])
    return [Paragraph("Kategori Serangan", styles["h2"]),
            Paragraph("Pengelompokan peringatan menurut tahapan serangan, sehingga terlihat "
                      "apakah aktivitas berhenti di percobaan atau sudah berlanjut ke tahap lanjut.",
                      styles["small"]),
            Spacer(1, 5),
            _table(rows, [12 * cm, 4 * cm], styles)]


def _daily_section(ds, styles):
    if not ds.daily_counts:
        return []
    peak = max((n for _, n in ds.daily_counts), default=0) or 1
    rows = [[Paragraph("<b>Tanggal</b>", styles["cellb"]),
             Paragraph("<b>Jumlah</b>", styles["cellb"]),
             Paragraph("<b>Grafik</b>", styles["cellb"])]]
    for day, n in ds.daily_counts:
        bar = "" if not n else "█" * max(1, round(n / peak * 28))
        rows.append([Paragraph(day, styles["cell"]), Paragraph(str(n), styles["cell"]),
                     Paragraph(f'<font color="#2563eb">{bar}</font>', styles["cell"])])
    return [Paragraph("Volume Harian", styles["h2"]),
            Paragraph("Jumlah peringatan per hari. Lonjakan tajam biasanya menandakan "
                      "kampanye serangan, bukan sekadar variasi normal.", styles["small"]),
            Spacer(1, 5),
            _table(rows, [3.5 * cm, 2.5 * cm, 10 * cm], styles)]


def _source_ip_section(ds, styles):
    if not ds.source_ips:
        return []
    rows = [[Paragraph("<b>Alamat IP sumber</b>", styles["cellb"]),
             Paragraph("<b>Peringatan</b>", styles["cellb"]),
             Paragraph("<b>Host terkena</b>", styles["cellb"]),
             Paragraph("<b>Pertama</b>", styles["cellb"]),
             Paragraph("<b>Terakhir</b>", styles["cellb"])]]
    for row in ds.source_ips[:15]:
        rows.append([
            Paragraph(_esc(row.source_ip), styles["cell"]),
            Paragraph(str(row.alert_count), styles["cell"]),
            Paragraph(_esc(", ".join(row.hostnames[:3]) or "-"), styles["cell"]),
            Paragraph(row.first_seen.strftime("%d/%m %H:%M") if row.first_seen else "-", styles["cell"]),
            Paragraph(row.last_seen.strftime("%d/%m %H:%M") if row.last_seen else "-", styles["cell"]),
        ])
    return [Paragraph("Alamat IP Sumber Teratas", styles["h2"]),
            Paragraph("Alamat asal yang paling sering memicu peringatan. Alamat yang sama "
                      "menyerang banyak host menandakan satu pelaku.", styles["small"]),
            Spacer(1, 5),
            _table(rows, [4 * cm, 2.2 * cm, 5.3 * cm, 2.5 * cm, 2.5 * cm], styles)]


def _rule_section(ds, styles):
    if not ds.top_rules:
        return []
    rows = [[Paragraph("<b>Aturan deteksi</b>", styles["cellb"]),
             Paragraph("<b>Jumlah</b>", styles["cellb"])]]
    for title, n in ds.top_rules[:12]:
        rows.append([Paragraph(_esc(title), styles["cell"]), Paragraph(str(n), styles["cell"])])
    return [Paragraph("Aturan Deteksi Paling Sering Terpicu", styles["h2"]),
            _table(rows, [13 * cm, 3 * cm], styles)]


def _mitre_section(ds, styles):
    if not ds.mitre_techniques:
        return []
    return [Paragraph("Teknik Serangan Teramati (MITRE ATT&CK)", styles["h2"]),
            Paragraph(_esc(", ".join(ds.mitre_techniques[:30])), styles["body"])]


def _case_sections(ds, styles):
    story = []
    for block in ds.cases:
        head = [
            Paragraph(_esc(block.title), styles["h3"]),
            _kv_table([
                ("Tingkat keparahan", label_severity(block.severity)),
                ("Status penanganan", label_status(block.status)),
                ("Tahap serangan", label_category(block.attack_family)),
                ("Jumlah peringatan", str(block.alert_count)),
                ("Host terdampak", ", ".join(block.affected_hosts) or "-"),
                ("Alamat IP sumber", ", ".join(block.source_ips) or "-"),
                ("Indikator kompromi", ", ".join(block.ioc_keys[:8]) or "-"),
                ("Mulai tercatat", block.created_at.strftime("%d/%m/%Y %H:%M UTC")),
                ("Penilaian AI", label_status(block.verdict) if block.verdict else "Belum ada"),
            ], styles),
            Spacer(1, 6),
        ]
        story.append(KeepTogether(head))
        if block.ai_summary:
            story.append(Paragraph("Ringkasan investigasi", styles["h3"]))
            story.extend(_narrative_blocks(block.ai_summary[:1800], styles))
        if block.mitre:
            story.append(Paragraph("Teknik teramati: " + _esc(", ".join(block.mitre[:12])), styles["small"]))
        story.append(Paragraph("Kronologi kejadian", styles["h3"]))
        story.extend(_timeline_flow(block.timeline, styles, limit=80))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", color=_RULE))
    return story


def _agent_sections(ds, styles):
    if not ds.agents:
        return [Paragraph("Tidak ada agen pada cakupan ini.", styles["body"])]
    rows = [[Paragraph("<b>Host</b>", styles["cellb"]),
             Paragraph("<b>Status</b>", styles["cellb"]),
             Paragraph("<b>Skor risiko</b>", styles["cellb"]),
             Paragraph("<b>Peringatan</b>", styles["cellb"]),
             Paragraph("<b>Kritis</b>", styles["cellb"]),
             Paragraph("<b>Perubahan berkas</b>", styles["cellb"]),
             Paragraph("<b>Higiene</b>", styles["cellb"])]]
    for agent in ds.agents[:40]:
        rows.append([
            Paragraph(_esc(agent.hostname), styles["cell"]),
            Paragraph(_esc(label_status(agent.status)), styles["cell"]),
            Paragraph(str(agent.risk_score), styles["cell"]),
            Paragraph(str(agent.alert_count), styles["cell"]),
            Paragraph(str(agent.critical_count), styles["cell"]),
            Paragraph(str(agent.fim_events), styles["cell"]),
            Paragraph(str(agent.hygiene_score) if agent.hygiene_score is not None else "-", styles["cell"]),
        ])
    return [Paragraph("Peringkat Risiko Agen", styles["h2"]),
            Paragraph("Skor risiko menggabungkan jumlah peringatan, peringatan kritis, status "
                      "koneksi, dan skor higiene. Skor lebih tinggi berarti perlu ditangani lebih dulu.",
                      styles["small"]),
            Spacer(1, 5),
            _table(rows, [4.4 * cm, 2 * cm, 2.1 * cm, 2.1 * cm, 1.6 * cm, 2.6 * cm, 1.7 * cm], styles)]


def _glossary(styles):
    story = [PageBreak(), Paragraph("Penjelasan Istilah", styles["h2"]),
             Paragraph("Bagian ini ditujukan bagi pembaca yang tidak berlatar belakang teknis.",
                       styles["small"]), Spacer(1, 6)]
    for term, meaning in GLOSSARY:
        story.append(Paragraph(f"<b>{_esc(term)}</b> — {_esc(meaning)}", styles["body"]))
        story.append(Spacer(1, 4))
    return story


def _limitations(ds, styles):
    if not ds.limitations:
        return []
    story = [Paragraph("Catatan Keterbatasan Data", styles["h2"])]
    for item in ds.limitations:
        story.append(Paragraph(f"• {_esc(item)}", styles["body"]))
    return story


def build_report_pdf(ds: ReportDataset) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, title=ds.title, author=ds.org_name or "SIEM",
        topMargin=1.8 * cm, bottomMargin=1.8 * cm, leftMargin=1.8 * cm, rightMargin=1.8 * cm,
    )
    styles = _styles()

    subtitle = ds.subject_label
    if ds.period_from and ds.period_to and ds.scope != "cases":
        subtitle = f"Periode {ds.period_from.isoformat()} s.d. {ds.period_to.isoformat()}"
        if ds.scope == "agents":
            subtitle += f"  •  {ds.subject_label}"

    story = _header(ds, styles, subtitle)
    story.extend(_executive_summary(ds, styles))
    story.extend(_key_numbers(ds, styles))
    story.extend(_limitations(ds, styles))

    story.append(Paragraph("Sebaran Tingkat Keparahan", styles["h2"]))
    story.append(Paragraph(
        "Tingkat keparahan menunjukkan seberapa mendesak sebuah peringatan perlu ditangani.",
        styles["small"]))
    story.append(Spacer(1, 5))
    story.append(_severity_bar(ds.severity_counts, styles))

    story.extend(_category_section(ds, styles))

    if ds.scope == "cases":
        story.append(PageBreak())
        story.append(Paragraph("Rincian Kasus", styles["h2"]))
        story.extend(_case_sections(ds, styles))
    elif ds.scope == "agents":
        story.append(PageBreak())
        story.extend(_agent_sections(ds, styles))

    if ds.daily_counts:
        story.append(PageBreak())
        story.extend(_daily_section(ds, styles))

    story.extend(_source_ip_section(ds, styles))
    story.extend(_rule_section(ds, styles))
    story.extend(_mitre_section(ds, styles))

    if ds.scope != "cases":
        story.append(PageBreak())
        story.append(Paragraph("Kronologi Kejadian", styles["h2"]))
        story.append(Paragraph(
            "Seluruh kejadian diurutkan menurut waktu. Untuk laporan dengan volume besar, "
            "berkas Excel memuat daftar lengkapnya.", styles["small"]))
        story.append(Spacer(1, 6))
        story.extend(_timeline_flow(ds.timeline, styles))

    story.extend(_glossary(styles))

    doc.build(story)
    return buf.getvalue()


def report_filename(ds: ReportDataset, extension: str) -> str:
    stamp = ds.generated_at.strftime("%Y%m%d")
    if ds.scope == "cases":
        slug = f"kasus-{len(ds.cases)}"
    elif ds.scope == "agents":
        slug = ds.agents[0].hostname if len(ds.agents) == 1 else f"agen-{len(ds.agents)}"
    elif ds.period_from and ds.period_to:
        slug = f"{ds.period_from}-{ds.period_to}"
    else:
        slug = "periode"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in slug).strip("-")
    return f"laporan-{ds.scope}-{safe}-{stamp}.{extension}"
