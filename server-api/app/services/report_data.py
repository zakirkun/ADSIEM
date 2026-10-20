# server-api/app/services/report_data.py
"""Gathers every number a report shows, so the PDF/Excel renderers stay pure.

Three report scopes share one shape (ReportDataset):

- "detailed"  — a date range: timeline, volume, category, level, source IP
- "cases"     — one or many cases: full evidence per campaign
- "agents"    — one agent, or the whole fleet ranked

Wording is deliberately plain Indonesian: each technical term keeps its
original name in parentheses so an executive can read the sentence and an
analyst can still match it to the dashboard.
"""
from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Agent, Alert, AlertNote, Case, CaseNote, FimEvent, HygieneSnapshot,
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

SEVERITY_LABEL_ID = {
    "critical": "Kritis",
    "high": "Tinggi",
    "medium": "Sedang",
    "low": "Rendah",
    "info": "Informasi",
}

KILL_CHAIN_LABEL_ID = {
    "reconnaissance": "Pengintaian (reconnaissance)",
    "initial_access": "Akses awal (initial access)",
    "credential_access": "Pengambilalihan kredensial (credential access)",
    "execution": "Eksekusi kode (execution)",
    "persistence": "Penetapan persistensi (persistence)",
    "privilege_escalation": "Eskalasi hak akses (privilege escalation)",
    "defense_evasion": "Penghindaran deteksi (defense evasion)",
    "lateral_movement": "Perpindahan lateral (lateral movement)",
    "collection": "Pengumpulan data (collection)",
    "command_and_control": "Kendali jarak jauh (command and control)",
    "exfiltration": "Pengeluaran data (exfiltration)",
    "impact": "Dampak langsung (impact)",
    "other": "Belum terklasifikasi",
}

CATEGORY_LABEL_ID = {
    "credential_access": "Percobaan pencurian kredensial (credential access)",
    "initial_access": "Percobaan akses awal (initial access)",
    "execution": "Eksekusi perintah berbahaya (execution)",
    "persistence": "Pemasangan persistensi (persistence)",
    "privilege_escalation": "Eskalasi hak akses (privilege escalation)",
    "defense_evasion": "Penghindaran deteksi (defense evasion)",
    "lateral_movement": "Perpindahan lateral (lateral movement)",
    "command_and_control": "Komunikasi dengan server penyerang (C2)",
    "exfiltration": "Pengeluaran data (exfiltration)",
    "collection": "Pengumpulan data (collection)",
    "reconnaissance": "Pengintaian (reconnaissance)",
    "impact": "Dampak langsung (impact)",
    "other": "Belum terklasifikasi",
}

STATUS_LABEL_ID = {
    "new": "Baru",
    "acknowledged": "Sudah ditinjau",
    "investigating": "Sedang diselidiki",
    "resolved": "Selesai",
    "closed": "Ditutup",
    "false_positive": "Positif palsu",
    "open": "Terbuka",
    "in_review": "Dalam peninjauan",
    "escalated": "Dieskalasi",
}


@dataclass
class TimelineEntry:
    occurred_at: datetime
    kind: str
    title: str
    detail: str = ""
    severity: str | None = None
    source_ip: str | None = None
    hostname: str | None = None
    actor: str = ""


@dataclass
class SourceIpRow:
    source_ip: str
    alert_count: int
    severities: dict = field(default_factory=dict)
    hostnames: list = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    country: str | None = None


@dataclass
class AgentRow:
    agent_id: str
    name: str
    hostname: str
    status: str
    version: str | None
    last_seen_at: datetime | None
    alert_count: int
    critical_count: int
    high_count: int
    fim_events: int
    hygiene_score: int | None
    os_name: str | None
    open_ports: int
    risk_score: int = 0


@dataclass
class CaseBlock:
    case_id: str
    title: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime | None
    attack_family: str
    affected_hosts: list
    ioc_keys: list
    verdict: str | None
    ai_summary: str
    alert_count: int
    timeline: list
    notes: list
    mitre: list
    source_ips: list


@dataclass
class ReportDataset:
    scope: str
    title: str
    org_name: str
    generated_at: datetime
    period_from: date | None = None
    period_to: date | None = None
    total_alerts: int = 0
    total_cases: int = 0
    avg_alerts_per_day: float = 0.0
    busiest_day: tuple[str, int] | None = None
    severity_counts: dict = field(default_factory=dict)
    category_counts: dict = field(default_factory=dict)
    status_counts: dict = field(default_factory=dict)
    daily_counts: list = field(default_factory=list)
    top_rules: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    source_ips: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    cases: list = field(default_factory=list)
    agents: list = field(default_factory=list)
    narrative: str = ""
    subject_label: str = ""
    limitations: list = field(default_factory=list)


def _day_bounds(date_from: date, date_to: date) -> tuple[datetime, datetime]:
    start = datetime.combine(date_from, time.min, tzinfo=timezone.utc)
    end = datetime.combine(date_to, time.max, tzinfo=timezone.utc)
    return start, end


def category_of(alert: Alert) -> str:
    return (alert.kill_chain_stage or "other") or "other"


def severity_rank(severity: str | None) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "info").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def label_severity(severity: str | None) -> str:
    key = (severity or "info").lower()
    return SEVERITY_LABEL_ID.get(key, key)


def label_category(category: str | None) -> str:
    key = (category or "other").lower()
    return CATEGORY_LABEL_ID.get(key, key)


def label_status(status: str | None) -> str:
    key = (status or "").lower()
    return STATUS_LABEL_ID.get(key, key or "-")


def _alert_entry(alert: Alert) -> TimelineEntry:
    detail_bits = []
    if alert.kill_chain_stage:
        detail_bits.append(f"Tahap: {label_category(alert.kill_chain_stage)}")
    if alert.ai_verdict:
        detail_bits.append(f"Penilaian AI: {label_status(alert.ai_verdict)}")
    if alert.duplicate_count:
        detail_bits.append(f"Pengulangan: {alert.duplicate_count}x")
    return TimelineEntry(
        occurred_at=alert.created_at,
        kind="alert",
        title=alert.title,
        detail=" | ".join(detail_bits),
        severity=alert.severity,
        source_ip=alert.source_ip,
        hostname=alert.hostname,
    )


async def _case_alerts(db: AsyncSession, case_ids: list[uuid.UUID]) -> list[Alert]:
    if not case_ids:
        return []
    rows = await db.execute(
        select(Alert)
        .where(Alert.case_id.in_(case_ids))
        .order_by(Alert.created_at.asc())
    )
    return list(rows.scalars().all())


async def _case_notes(db: AsyncSession, case_ids: list[uuid.UUID]) -> list[CaseNote]:
    if not case_ids:
        return []
    rows = await db.execute(
        select(CaseNote)
        .where(CaseNote.case_id.in_(case_ids))
        .order_by(CaseNote.created_at.asc())
    )
    return list(rows.scalars().all())


def _build_case_block(
    case: Case,
    alerts: list[Alert],
    notes: list[CaseNote],
    alert_notes: dict[uuid.UUID, list[AlertNote]],
) -> CaseBlock:
    ioc = case.ioc_data or {}
    timeline: list[TimelineEntry] = []
    for alert in alerts:
        timeline.append(_alert_entry(alert))
        for note in alert_notes.get(alert.id, []):
            timeline.append(TimelineEntry(
                occurred_at=note.created_at,
                kind="alert_note",
                title="Catatan pada peringatan",
                detail=(note.content or "")[:400],
                severity=alert.severity,
                source_ip=alert.source_ip,
                hostname=alert.hostname,
                actor="Analis",
            ))
    for note in notes:
        timeline.append(TimelineEntry(
            occurred_at=note.created_at,
            kind="case_note",
            title="Catatan investigasi",
            detail=(note.content or "")[:400],
            actor="AI" if note.is_ai_generated else "Analis",
        ))
    timeline.sort(key=lambda e: e.occurred_at)

    mitre: list[str] = []
    for alert in alerts:
        for technique in alert.mitre_techniques or []:
            if technique not in mitre:
                mitre.append(technique)

    ips: list[str] = []
    for alert in alerts:
        if alert.source_ip and alert.source_ip not in ips:
            ips.append(alert.source_ip)

    return CaseBlock(
        case_id=str(case.id),
        title=case.title,
        severity=case.severity,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        attack_family=ioc.get("attack_family") or "other",
        affected_hosts=list(ioc.get("affected_hosts") or ioc.get("hosts") or []),
        ioc_keys=list(ioc.get("ioc_keys") or []),
        verdict=ioc.get("verdict"),
        ai_summary=case.description or case.ai_reasoning or "",
        alert_count=len(alerts),
        timeline=timeline,
        notes=[(n.created_at, n.content or "", bool(n.is_ai_generated)) for n in notes],
        mitre=mitre,
        source_ips=ips,
    )


async def build_detailed_dataset(
    db: AsyncSession,
    org_name: str,
    date_from: date,
    date_to: date,
    group_filter: str | None,
    narrative: str = "",
) -> ReportDataset:
    start, end = _day_bounds(date_from, date_to)

    q = select(Alert).where(Alert.created_at >= start, Alert.created_at <= end)
    if group_filter:
        q = q.where(Alert.group_id == group_filter)
    alerts = list((await db.execute(q.order_by(Alert.created_at.asc()))).scalars().all())

    severity_counts = Counter((a.severity or "info").lower() for a in alerts)
    category_counts = Counter(category_of(a) for a in alerts)
    status_counts = Counter((a.status or "new").lower() for a in alerts)
    top_rules = Counter(a.title for a in alerts).most_common(15)

    daily = Counter(a.created_at.date().isoformat() for a in alerts)
    day_count = max((date_to - date_from).days + 1, 1)
    daily_counts = []
    cursor = date_from
    while cursor <= date_to:
        key = cursor.isoformat()
        daily_counts.append((key, daily.get(key, 0)))
        cursor += timedelta(days=1)

    ip_alerts: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip:
            ip_alerts[alert.source_ip].append(alert)

    source_ips = []
    for ip, group in sorted(ip_alerts.items(), key=lambda kv: len(kv[1]), reverse=True)[:20]:
        hosts = sorted({a.hostname for a in group if a.hostname})
        source_ips.append(SourceIpRow(
            source_ip=ip,
            alert_count=len(group),
            severities=dict(Counter((a.severity or "info").lower() for a in group)),
            hostnames=hosts,
            first_seen=min(a.created_at for a in group),
            last_seen=max(a.created_at for a in group),
        ))

    mitre: list[str] = []
    for alert in alerts:
        for technique in alert.mitre_techniques or []:
            if technique not in mitre:
                mitre.append(technique)

    case_q = select(Case).where(Case.created_at >= start, Case.created_at <= end)
    if group_filter:
        case_q = case_q.where(Case.group_id == group_filter)
    total_cases = len((await db.execute(case_q)).scalars().all())

    busiest = max(daily_counts, key=lambda kv: kv[1]) if daily_counts else None
    if busiest and busiest[1] == 0:
        busiest = None

    return ReportDataset(
        scope="detailed",
        title="Laporan Detail Aktivitas Keamanan",
        org_name=org_name,
        generated_at=datetime.now(timezone.utc),
        period_from=date_from,
        period_to=date_to,
        total_alerts=len(alerts),
        total_cases=total_cases,
        avg_alerts_per_day=round(len(alerts) / day_count, 2),
        busiest_day=busiest,
        severity_counts=dict(severity_counts),
        category_counts=dict(category_counts),
        status_counts=dict(status_counts),
        daily_counts=daily_counts,
        top_rules=top_rules,
        mitre_techniques=mitre[:40],
        source_ips=source_ips,
        timeline=[_alert_entry(a) for a in alerts],
        narrative=narrative,
        subject_label=f"{date_from.isoformat()} s.d. {date_to.isoformat()}",
    )


async def build_case_dataset(
    db: AsyncSession,
    org_name: str,
    case_ids: list[uuid.UUID],
    group_filter: str | None,
    narrative: str = "",
) -> ReportDataset:
    q = select(Case).where(Case.id.in_(case_ids))
    if group_filter:
        q = q.where(Case.group_id == group_filter)
    cases = list((await db.execute(q.order_by(Case.created_at.asc()))).scalars().all())

    found_ids = {c.id for c in cases}
    missing = [str(cid) for cid in case_ids if cid not in found_ids]

    alerts = await _case_alerts(db, list(found_ids))
    alerts_by_case: dict[uuid.UUID, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.case_id:
            alerts_by_case[alert.case_id].append(alert)

    alert_ids = [a.id for a in alerts]
    alert_notes: dict[uuid.UUID, list[AlertNote]] = defaultdict(list)
    if alert_ids:
        rows = await db.execute(
            select(AlertNote)
            .where(AlertNote.alert_id.in_(alert_ids))
            .order_by(AlertNote.created_at.asc())
        )
        for note in rows.scalars().all():
            alert_notes[note.alert_id].append(note)

    notes = await _case_notes(db, list(found_ids))
    notes_by_case: dict[uuid.UUID, list[CaseNote]] = defaultdict(list)
    for note in notes:
        notes_by_case[note.case_id].append(note)

    blocks = [
        _build_case_block(case, alerts_by_case.get(case.id, []), notes_by_case.get(case.id, []), alert_notes)
        for case in cases
    ]

    timeline: list[TimelineEntry] = []
    for block in blocks:
        timeline.extend(block.timeline)
    timeline.sort(key=lambda e: e.occurred_at)

    severity_counts = Counter((c.severity or "info").lower() for c in cases)
    category_counts = Counter(b.attack_family for b in blocks)
    status_counts = Counter((c.status or "open").lower() for c in cases)

    mitre: list[str] = []
    for block in blocks:
        for technique in block.mitre:
            if technique not in mitre:
                mitre.append(technique)

    ip_counter = Counter()
    for alert in alerts:
        if alert.source_ip:
            ip_counter[alert.source_ip] += 1
    source_ips = [
        SourceIpRow(source_ip=ip, alert_count=count)
        for ip, count in ip_counter.most_common(20)
    ]

    limitations = []
    if missing:
        limitations.append(
            f"{len(missing)} kasus tidak ditemukan atau berada di luar cakupan grup Anda."
        )
    no_alert_cases = [b.title for b in blocks if b.alert_count == 0]
    if no_alert_cases:
        limitations.append(
            "Kasus berikut belum memiliki peringatan tertaut sehingga kronologinya kosong: "
            + "; ".join(no_alert_cases[:5])
        )

    return ReportDataset(
        scope="cases",
        title="Laporan Investigasi Kasus",
        org_name=org_name,
        generated_at=datetime.now(timezone.utc),
        total_alerts=len(alerts),
        total_cases=len(blocks),
        severity_counts=dict(severity_counts),
        category_counts=dict(category_counts),
        status_counts=dict(status_counts),
        mitre_techniques=mitre[:40],
        source_ips=source_ips,
        timeline=timeline,
        cases=blocks,
        narrative=narrative,
        subject_label=f"{len(blocks)} kasus",
        limitations=limitations,
    )


async def build_agent_dataset(
    db: AsyncSession,
    org_name: str,
    date_from: date,
    date_to: date,
    group_filter: str | None,
    agent_ids: list[uuid.UUID] | None = None,
    narrative: str = "",
) -> ReportDataset:
    start, end = _day_bounds(date_from, date_to)

    q = select(Agent)
    if group_filter:
        q = q.where(Agent.group_id == group_filter)
    if agent_ids:
        q = q.where(Agent.id.in_(agent_ids))
    agents = list((await db.execute(q.order_by(Agent.hostname.asc()))).scalars().all())
    selected_ids = [a.id for a in agents]

    alert_q = select(Alert).where(
        Alert.created_at >= start, Alert.created_at <= end, Alert.agent_id.in_(selected_ids)
    )
    if group_filter:
        alert_q = alert_q.where(Alert.group_id == group_filter)
    alerts = list((await db.execute(alert_q)).scalars().all()) if selected_ids else []

    alerts_by_agent: dict[uuid.UUID, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.agent_id:
            alerts_by_agent[alert.agent_id].append(alert)

    fim_q = select(FimEvent).where(
        FimEvent.detected_at >= start, FimEvent.detected_at <= end, FimEvent.agent_id.in_(selected_ids)
    )
    if group_filter:
        fim_q = fim_q.where(FimEvent.group_id == group_filter)
    fim_events = list((await db.execute(fim_q)).scalars().all()) if selected_ids else []
    fim_by_agent = Counter(e.agent_id for e in fim_events)

    hygiene: dict[uuid.UUID, HygieneSnapshot] = {}
    if selected_ids:
        rows = await db.execute(
            select(HygieneSnapshot)
            .where(HygieneSnapshot.agent_id.in_(selected_ids))
            .order_by(HygieneSnapshot.collected_at.desc())
        )
        for snap in rows.scalars().all():
            hygiene.setdefault(snap.agent_id, snap)

    rows_out: list[AgentRow] = []
    for agent in agents:
        own = alerts_by_agent.get(agent.id, [])
        sev = Counter((a.severity or "info").lower() for a in own)
        snap = hygiene.get(agent.id)
        row = AgentRow(
            agent_id=str(agent.id),
            name=agent.name,
            hostname=agent.hostname,
            status=agent.status,
            version=agent.version,
            last_seen_at=agent.last_seen_at,
            alert_count=len(own),
            critical_count=sev.get("critical", 0),
            high_count=sev.get("high", 0),
            fim_events=fim_by_agent.get(agent.id, 0),
            hygiene_score=snap.hygiene_score if snap else None,
            os_name=snap.os_name if snap else None,
            open_ports=len(snap.open_ports or []) if snap else 0,
        )
        row.risk_score = (
            row.critical_count * 10
            + row.high_count * 4
            + min(row.alert_count, 50)
            + (25 if agent.status != "online" else 0)
            + (20 if row.hygiene_score is not None and row.hygiene_score < 60 else 0)
        )
        rows_out.append(row)

    rows_out.sort(key=lambda r: (r.risk_score, r.alert_count), reverse=True)

    severity_counts = Counter((a.severity or "info").lower() for a in alerts)
    category_counts = Counter(category_of(a) for a in alerts)
    daily = Counter(a.created_at.date().isoformat() for a in alerts)
    day_count = max((date_to - date_from).days + 1, 1)
    daily_counts = []
    cursor = date_from
    while cursor <= date_to:
        key = cursor.isoformat()
        daily_counts.append((key, daily.get(key, 0)))
        cursor += timedelta(days=1)

    timeline = sorted((_alert_entry(a) for a in alerts), key=lambda e: e.occurred_at)
    ip_counter = Counter(a.source_ip for a in alerts if a.source_ip)
    source_ips = [SourceIpRow(source_ip=ip, alert_count=n) for ip, n in ip_counter.most_common(20)]

    mitre: list[str] = []
    for alert in alerts:
        for technique in alert.mitre_techniques or []:
            if technique not in mitre:
                mitre.append(technique)

    offline = [r.hostname for r in rows_out if r.status != "online"]
    limitations = []
    if offline:
        limitations.append(
            f"{len(offline)} agen sedang tidak daring sehingga datanya tidak lengkap: "
            + "; ".join(offline[:5])
        )

    subject = rows_out[0].hostname if len(rows_out) == 1 else f"{len(rows_out)} agen"
    title = "Laporan Kesehatan dan Aktivitas Agen" if len(rows_out) != 1 else "Laporan Aktivitas Agen"

    return ReportDataset(
        scope="agents",
        title=title,
        org_name=org_name,
        generated_at=datetime.now(timezone.utc),
        period_from=date_from,
        period_to=date_to,
        total_alerts=len(alerts),
        avg_alerts_per_day=round(len(alerts) / day_count, 2),
        severity_counts=dict(severity_counts),
        category_counts=dict(category_counts),
        daily_counts=daily_counts,
        top_rules=Counter(a.title for a in alerts).most_common(15),
        mitre_techniques=mitre[:40],
        source_ips=source_ips,
        timeline=timeline,
        agents=rows_out,
        narrative=narrative,
        subject_label=subject,
        limitations=limitations,
    )


def dataset_to_dict(ds: ReportDataset) -> dict:
    """Plain-JSON view of a dataset, for the Excel writer and for API clients."""
    def iso(value):
        return value.isoformat() if isinstance(value, datetime) else value

    return {
        "scope": ds.scope,
        "title": ds.title,
        "org_name": ds.org_name,
        "generated_at": iso(ds.generated_at),
        "subject_label": ds.subject_label,
        "period_from": ds.period_from.isoformat() if ds.period_from else None,
        "period_to": ds.period_to.isoformat() if ds.period_to else None,
        "total_alerts": ds.total_alerts,
        "total_cases": ds.total_cases,
        "avg_alerts_per_day": ds.avg_alerts_per_day,
        "busiest_day": ds.busiest_day,
        "severity_counts": ds.severity_counts,
        "category_counts": ds.category_counts,
        "status_counts": ds.status_counts,
        "daily_counts": ds.daily_counts,
        "top_rules": ds.top_rules,
        "mitre_techniques": ds.mitre_techniques,
        "narrative": ds.narrative,
        "limitations": ds.limitations,
        "timeline": [
            {
                "occurred_at": e.occurred_at.isoformat(),
                "kind": e.kind,
                "title": e.title,
                "detail": e.detail,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "hostname": e.hostname,
                "actor": e.actor,
            }
            for e in ds.timeline
        ],
        "source_ips": [
            {
                "source_ip": r.source_ip,
                "alert_count": r.alert_count,
                "severities": r.severities,
                "hostnames": r.hostnames,
                "first_seen": iso(r.first_seen),
                "last_seen": iso(r.last_seen),
            }
            for r in ds.source_ips
        ],
        "cases": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "severity": c.severity,
                "status": c.status,
                "created_at": iso(c.created_at),
                "attack_family": c.attack_family,
                "affected_hosts": c.affected_hosts,
                "ioc_keys": c.ioc_keys,
                "verdict": c.verdict,
                "alert_count": c.alert_count,
                "mitre": c.mitre,
                "source_ips": c.source_ips,
                "ai_summary": c.ai_summary,
                "timeline": [
                    {
                        "occurred_at": e.occurred_at.isoformat(),
                        "kind": e.kind,
                        "title": e.title,
                        "detail": e.detail,
                        "actor": e.actor,
                    }
                    for e in c.timeline
                ],
            }
            for c in ds.cases
        ],
        "agents": [
            {
                "agent_id": a.agent_id,
                "name": a.name,
                "hostname": a.hostname,
                "status": a.status,
                "version": a.version,
                "last_seen_at": iso(a.last_seen_at),
                "alert_count": a.alert_count,
                "critical_count": a.critical_count,
                "high_count": a.high_count,
                "fim_events": a.fim_events,
                "hygiene_score": a.hygiene_score,
                "os_name": a.os_name,
                "open_ports": a.open_ports,
                "risk_score": a.risk_score,
            }
            for a in ds.agents
        ],
    }


def dataset_prompt_facts(ds: ReportDataset) -> str:
    sev_lines = ", ".join(
        f"{label_severity(s)}={ds.severity_counts.get(s, 0)}" for s in SEVERITY_ORDER
        if ds.severity_counts.get(s)
    ) or "tidak ada"
    cat_lines = ", ".join(
        f"{label_category(c)}={n}"
        for c, n in sorted(ds.category_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
    ) or "tidak ada"
    ip_lines = ", ".join(f"{r.source_ip} ({r.alert_count} peringatan)" for r in ds.source_ips[:8]) or "tidak ada"
    parts = [
        f"Cakupan laporan: {ds.subject_label}",
        f"Total peringatan: {ds.total_alerts}",
        f"Rata-rata peringatan per hari: {ds.avg_alerts_per_day}",
        f"Total kasus: {ds.total_cases}",
        f"Sebaran tingkat keparahan: {sev_lines}",
        f"Sebaran kategori serangan: {cat_lines}",
        f"Alamat IP sumber teratas: {ip_lines}",
    ]
    if ds.agents:
        top = ds.agents[:5]
        parts.append("Agen paling berisiko: " + ", ".join(
            f"{a.hostname} (risiko {a.risk_score}, {a.alert_count} peringatan)" for a in top
        ))
    if ds.cases:
        parts.append("Kasus: " + ", ".join(
            f"{c.title} [{label_severity(c.severity)}, {c.alert_count} peringatan, "
            f"tahap {label_category(c.attack_family)}]" for c in ds.cases[:6]
        ))
    return "\n".join(f"- {p}" for p in parts)
