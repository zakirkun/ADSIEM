# tests/server-api/test_report_build.int.py
"""Report gathering against a real Postgres: case membership comes from
alerts.case_id, averages are per calendar day, and group scoping holds."""
import asyncio
import os
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

DB_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DB_URL or os.environ.get("DATABASE_URL") != DB_URL,
    reason="needs TEST_DATABASE_URL (= DATABASE_URL)",
)

_LOOP = asyncio.new_event_loop()


def _run(coro):
    return _LOOP.run_until_complete(coro)


@pytest.fixture(scope="module")
def env():
    from sqlalchemy import text

    from app.core.database import Base, engine
    import app.models.models  # noqa: F401

    async def setup():
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)

    async def teardown():
        await engine.dispose()

    _run(setup())
    yield SimpleEnv()
    _run(teardown())

class SimpleEnv:
    pass


def _session():
    from app.core.database import AsyncSessionLocal
    return AsyncSessionLocal()


async def _seed(group_id="g1"):
    from app.models.models import Agent, Alert, Case

    now = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    async with _session() as db:
        agent = Agent(name="web-01", hostname="web-01", group_id=group_id, token_hash="x")
        db.add(agent)
        await db.flush()

        case = Case(title="Kampanye SSH", severity="high", status="open", group_id=group_id,
                    created_at=now, ioc_data={"affected_hosts": ["web-01"], "attack_family": "credential_access"})
        db.add(case)
        await db.flush()

        alerts = [
            Alert(title="SSH brute force", severity="critical", group_id=group_id, agent_id=agent.id,
                  case_id=case.id, source_ip="203.0.113.9", hostname="web-01",
                  kill_chain_stage="credential_access", created_at=now),
            Alert(title="SSH brute force", severity="high", group_id=group_id, agent_id=agent.id,
                  case_id=case.id, source_ip="203.0.113.9", hostname="web-01",
                  kill_chain_stage="credential_access", created_at=now + timedelta(days=2)),
            Alert(title="Webshell upload", severity="medium", group_id=group_id, agent_id=agent.id,
                  source_ip="198.51.100.7", hostname="web-02",
                  kill_chain_stage="execution", created_at=now),
            Alert(title="Other group alert", severity="low", group_id="g2",
                  source_ip="192.0.2.1", created_at=now),
        ]
        db.add_all(alerts)
        await db.commit()
        return {"case": case.id, "agent": agent.id}


@pytest.fixture(scope="module")
def seeded(env):
    from sqlalchemy import text
    from app.core.database import engine

    async def wipe():
        async with engine.begin() as conn:
            for table in ("alerts", "cases", "agents"):
                await conn.execute(text(f"DELETE FROM {table}"))

    _run(wipe())
    return _run(_seed())


def test_case_report_uses_case_id_not_time_window(seeded):
    from app.services.report_data import build_case_dataset

    async def go():
        async with _session() as db:
            return await build_case_dataset(db, "PT Contoh", [seeded["case"]], "g1")

    ds = _run(go())
    assert len(ds.cases) == 1
    assert ds.cases[0].alert_count == 2
    assert ds.cases[0].severity == "high"
    assert ds.cases[0].attack_family == "credential_access"
    assert ds.total_alerts == 2


def test_case_report_includes_alert_two_days_apart(seeded):
    from app.services.report_data import build_case_dataset

    async def go():
        async with _session() as db:
            return await build_case_dataset(db, "PT Contoh", [seeded["case"]], "g1")

    ds = _run(go())
    stamps = [e.occurred_at for e in ds.cases[0].timeline]
    assert len(stamps) == 2
    assert (max(stamps) - min(stamps)).days == 2


def test_case_report_hides_other_groups_case(seeded):
    from app.services.report_data import build_case_dataset

    async def go():
        async with _session() as db:
            return await build_case_dataset(db, "PT Contoh", [seeded["case"]], "g2")

    ds = _run(go())
    assert ds.cases == []
    assert ds.limitations


def test_detailed_report_average_is_per_calendar_day(seeded):
    from app.services.report_data import build_detailed_dataset

    async def go():
        async with _session() as db:
            return await build_detailed_dataset(
                db, "PT Contoh", date(2026, 10, 1), date(2026, 10, 5), "g1")

    ds = _run(go())
    assert ds.total_alerts == 3
    assert len(ds.daily_counts) == 5
    assert ds.avg_alerts_per_day == 0.6
    assert ds.busiest_day[0] == "2026-10-03"


def test_detailed_report_groups_by_category_and_source_ip(seeded):
    from app.services.report_data import build_detailed_dataset

    async def go():
        async with _session() as db:
            return await build_detailed_dataset(
                db, "PT Contoh", date(2026, 10, 1), date(2026, 10, 5), "g1")

    ds = _run(go())
    assert ds.category_counts["credential_access"] == 2
    assert ds.category_counts["execution"] == 1
    top = ds.source_ips[0]
    assert top.source_ip == "203.0.113.9"
    assert top.alert_count == 2
    assert top.severities["critical"] == 1


def test_detailed_report_excludes_other_groups(seeded):
    from app.services.report_data import build_detailed_dataset

    async def go():
        async with _session() as db:
            return await build_detailed_dataset(
                db, "PT Contoh", date(2026, 10, 1), date(2026, 10, 5), "g1")

    ds = _run(go())
    assert all(ip.source_ip != "192.0.2.1" for ip in ds.source_ips)


def test_agent_report_ranks_by_risk_and_counts_alerts(seeded):
    from app.services.report_data import build_agent_dataset

    async def go():
        async with _session() as db:
            return await build_agent_dataset(
                db, "PT Contoh", date(2026, 10, 1), date(2026, 10, 5), "g1")

    ds = _run(go())
    assert len(ds.agents) == 1
    row = ds.agents[0]
    assert row.hostname == "web-01"
    assert row.alert_count == 3
    assert row.critical_count == 1
    assert row.high_count == 1
    assert row.risk_score > 0


def test_agent_report_scoped_to_single_agent(seeded):
    from app.services.report_data import build_agent_dataset

    async def go():
        async with _session() as db:
            return await build_agent_dataset(
                db, "PT Contoh", date(2026, 10, 1), date(2026, 10, 5), "g1",
                agent_ids=[uuid.uuid4()])

    ds = _run(go())
    assert ds.agents == []


def test_case_report_flags_case_without_alerts(seeded):
    from app.models.models import Case
    from app.services.report_data import build_case_dataset

    async def make():
        async with _session() as db:
            case = Case(title="Kasus tanpa peringatan", severity="low", status="open", group_id="g1",
                        created_at=datetime(2026, 10, 4, tzinfo=timezone.utc), ioc_data={})
            db.add(case)
            await db.commit()
            return case.id

    case_id = _run(make())

    async def go():
        async with _session() as db:
            return await build_case_dataset(db, "PT Contoh", [case_id], "g1")

    ds = _run(go())
    assert ds.cases[0].alert_count == 0
    assert any("belum memiliki peringatan" in item for item in ds.limitations)
