# server-api/app/api/routes/reports.py
import json
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_scoped_group, require_permission
from app.core.llm_client import generate_text
from app.models.models import Alert, Case, PlatformSetting
from app.schemas.schemas import ReportGenerateRequest, ReportRequest
from app.services.report_data import (
    build_agent_dataset, build_case_dataset, build_detailed_dataset, dataset_prompt_facts,
)
from app.services.report_excel import build_report_excel
from app.services.report_pdf import build_report_pdf, report_filename

router = APIRouter(prefix="/api/reports", tags=["reports"])
Perm = require_permission("alerts:read")

MAX_REPORT_DAYS = 366
MAX_CASES_PER_REPORT = 50


async def _get_setting(db: AsyncSession, key: str, default: str = "") -> str:
    row = (await db.execute(select(PlatformSetting).where(PlatformSetting.key == key))).scalar_one_or_none()
    return (row.value if row and row.value else default)


def _narrative_prompt(facts: str, language: str, scope: str) -> str:
    audience = {
        "detailed": "an executive security briefing covering a period of activity",
        "cases": "an executive briefing on one or more specific security incidents",
        "agents": "an executive briefing on endpoint health and per-host risk",
    }.get(scope, "an executive security briefing")
    return f"""You are a senior SOC analyst writing {audience}.

Verified facts (do not invent numbers or hostnames beyond these):
{facts}

Write exactly three short paragraphs in {language}, using formal, plain language that a
non-technical executive can follow. Keep every technical term but explain it in
parentheses the first time it appears (e.g. "serangan brute force (percobaan login
berulang)"). Structure:
1. What happened overall in this scope.
2. The most important findings and why they matter to the business.
3. Concrete priorities for the reader's next decision.

Rules: no bullet points, no markdown, no headings, maximum 260 words, and never claim
an action was taken. Respond with the three paragraphs only."""


async def _narrative(db: AsyncSession, ds, include: bool, language: str) -> str:
    if not include:
        return ""
    api_key = await _get_setting(db, "ninerouter_api_key", "")
    if not api_key:
        return ""
    model = await _get_setting(db, "ninerouter_model", "combo")
    prompt = _narrative_prompt(dataset_prompt_facts(ds), language, ds.scope)
    try:
        return await generate_text(api_key, model, prompt, max_tokens=2000, db=db)
    except Exception:
        return ""


def _resolve_period(body: ReportRequest) -> tuple[date, date]:
    today = datetime.now(timezone.utc).date()
    date_from = body.date_from or (today - timedelta(days=6))
    date_to = body.date_to or today
    if date_from > date_to:
        raise HTTPException(status_code=422, detail="Tanggal awal harus sebelum tanggal akhir")
    if (date_to - date_from).days + 1 > MAX_REPORT_DAYS:
        raise HTTPException(
            status_code=422,
            detail=f"Rentang laporan maksimum {MAX_REPORT_DAYS} hari",
        )
    return date_from, date_to


@router.post("/generate")
async def generate_report(
    body: ReportGenerateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    range_from = datetime.combine(body.date_from, datetime.min.time(), tzinfo=timezone.utc)
    range_to = datetime.combine(body.date_to, datetime.max.time(), tzinfo=timezone.utc)

    alert_q = select(Alert).where(Alert.created_at >= range_from, Alert.created_at <= range_to)
    if group_filter:
        alert_q = alert_q.where(Alert.group_id == group_filter)
    alerts = (await db.execute(alert_q)).scalars().all()

    severity_counts = dict(Counter(a.severity for a in alerts))
    top_rules = Counter(a.title for a in alerts).most_common(10)

    case_filter_sql = "AND group_id = :group_id" if group_filter else ""
    params = {"date_from": range_from, "date_to": range_to}
    if group_filter:
        params["group_id"] = group_filter

    verdict_rows = (await db.execute(text(f"""
        SELECT COALESCE(ioc_data->>'verdict', 'unknown') AS verdict, COUNT(*) AS cnt
        FROM cases
        WHERE created_at >= :date_from AND created_at <= :date_to
          AND created_by_ai = TRUE {case_filter_sql}
        GROUP BY COALESCE(ioc_data->>'verdict', 'unknown')
    """), params)).mappings().all()
    verdict_counts = {r["verdict"]: r["cnt"] for r in verdict_rows}

    total_cases_row = (await db.execute(text(f"""
        SELECT COUNT(*) AS cnt FROM cases
        WHERE created_at >= :date_from AND created_at <= :date_to {case_filter_sql}
    """), params)).mappings().first()
    total_cases = total_cases_row["cnt"] if total_cases_row else 0

    org_name = await _get_setting(db, "org_name", "SIEM Security Report")

    prompt = f"""You are an AI SOC analyst writing an executive security report.

Data for the period {body.date_from.isoformat()} to {body.date_to.isoformat()}:
- Total alerts: {len(alerts)}
- Total cases: {total_cases}
- Severity breakdown: {json.dumps(severity_counts)}
- AI verdict distribution: {json.dumps(verdict_counts)}

Write a 3-paragraph executive summary IN {body.language.upper()} (the entire response must be in {body.language}):
1. Overview of the period's threat landscape
2. Key findings (campaigns detected, top techniques, notable patterns)
3. Recommended focus areas going forward

Keep it concise — max 220 words total. No bullet points, pure paragraphs. Respond with plain text only, no markdown."""

    api_key = await _get_setting(db, "ninerouter_api_key", "")
    model = await _get_setting(db, "ninerouter_model", "combo")
    narrative = await generate_text(api_key, model, prompt, max_tokens=2000, db=db)

    from app.services.report_data import ReportDataset

    legacy = ReportDataset(
        scope="detailed",
        title="Security Operations Report",
        org_name=org_name,
        generated_at=datetime.now(timezone.utc),
        period_from=body.date_from,
        period_to=body.date_to,
        total_alerts=len(alerts),
        total_cases=total_cases,
        severity_counts=severity_counts,
        top_rules=top_rules,
        narrative=narrative,
        subject_label=f"{body.date_from.isoformat()} s.d. {body.date_to.isoformat()}",
    )

    pdf_bytes = build_report_pdf(legacy)
    filename = f"security-report-{body.date_from.isoformat()}-to-{body.date_to.isoformat()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/build")
async def build_report(
    body: ReportRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    org_name = await _get_setting(db, "org_name", "SIEM Security Report")

    if body.scope == "detailed":
        date_from, date_to = _resolve_period(body)
        ds = await build_detailed_dataset(db, org_name, date_from, date_to, group_filter)
    elif body.scope == "cases":
        if not body.case_ids:
            raise HTTPException(status_code=422, detail="Pilih minimal satu kasus")
        if len(body.case_ids) > MAX_CASES_PER_REPORT:
            raise HTTPException(
                status_code=422,
                detail=f"Maksimum {MAX_CASES_PER_REPORT} kasus per laporan",
            )
        ds = await build_case_dataset(db, org_name, list(body.case_ids), group_filter)
        if not ds.cases:
            raise HTTPException(status_code=404, detail="Kasus tidak ditemukan")
    else:
        date_from, date_to = _resolve_period(body)
        ds = await build_agent_dataset(
            db, org_name, date_from, date_to, group_filter,
            agent_ids=list(body.agent_ids) or None,
        )
        if not ds.agents:
            raise HTTPException(status_code=404, detail="Agen tidak ditemukan")

    ds.narrative = await _narrative(db, ds, body.include_narrative, body.language)

    if body.format == "excel":
        content = build_report_excel(ds)
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename = report_filename(ds, "xlsx")
    else:
        content = build_report_pdf(ds)
        media = "application/pdf"
        filename = report_filename(ds, "pdf")

    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/options")
async def report_options(
    db: Annotated[AsyncSession, Depends(get_db)],
    group_filter: Annotated[str | None, Depends(get_scoped_group)],
    _=Depends(Perm),
):
    case_q = select(Case).order_by(Case.created_at.desc()).limit(200)
    if group_filter:
        case_q = case_q.where(Case.group_id == group_filter)
    cases = (await db.execute(case_q)).scalars().all()

    from app.models.models import Agent

    agent_q = select(Agent).order_by(Agent.hostname.asc())
    if group_filter:
        agent_q = agent_q.where(Agent.group_id == group_filter)
    agents = (await db.execute(agent_q)).scalars().all()

    return {
        "cases": [
            {
                "id": str(c.id),
                "title": c.title,
                "severity": c.severity,
                "status": c.status,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in cases
        ],
        "agents": [
            {
                "id": str(a.id),
                "hostname": a.hostname,
                "name": a.name,
                "status": a.status,
            }
            for a in agents
        ],
    }
