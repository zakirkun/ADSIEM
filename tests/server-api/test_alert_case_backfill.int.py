# tests/server-api/test_alert_case_backfill.int.py
"""Backfill links legacy alerts to their campaign case by IP, and must not
re-link on the next startup."""
import asyncio
import json
import os
import uuid

import pytest
from sqlalchemy import text

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
    yield True
    _run(teardown())


async def _reset():
    from app.core.database import engine

    async with engine.begin() as conn:
        for table in ("alerts", "cases", "agents", "platform_settings"):
            await conn.execute(text(f"DELETE FROM {table}"))


async def _seed_case(conn, title, ioc_keys, status="open", merged=None):
    case_id = uuid.uuid4()
    ioc = {"ioc_keys": ioc_keys}
    if merged:
        ioc["merged_into"] = merged
    await conn.execute(
        text("INSERT INTO cases (id,title,severity,status,group_id,created_by_ai,ioc_data,search_intel) "
             "VALUES (:i,:t,'high',:s,'default',false,CAST(:ioc AS jsonb),'{}')"),
        {"i": case_id, "t": title, "s": status, "ioc": json.dumps(ioc)},
    )
    return case_id


async def _seed_alert(conn, agent_id, source_ip):
    alert_id = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO alerts (id,title,severity,status,group_id,agent_id,source_ip,"
             "duplicate_count,mitre_techniques,context) "
             "VALUES (:i,:t,'high','new','default',:ag,:ip,0,'[]','{}')"),
        {"i": alert_id, "t": f"alert-{source_ip}", "ag": agent_id, "ip": source_ip},
    )
    return alert_id


async def _seed_agent(conn):
    agent_id = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO agents (id,name,hostname,group_id,token_hash,status,approved,is_isolated) "
             "VALUES (:i,'a','h','default','x','online',true,false)"),
        {"i": agent_id},
    )
    return agent_id


def test_backfill_links_alert_to_case_naming_its_ip(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            case_id = await _seed_case(conn, "campaign", ["ip:203.0.113.9"])
            alert_id = await _seed_alert(conn, agent, "203.0.113.9")
        count = await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            linked = (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar()
        return count, linked, case_id

    count, linked, case_id = _run(go())
    assert count == 1
    assert linked == case_id


def test_backfill_skips_merged_case(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            await _seed_case(conn, "merged", ["ip:198.51.100.5"], merged=str(uuid.uuid4()))
            alert_id = await _seed_alert(conn, agent, "198.51.100.5")
        await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            return (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar()

    assert _run(go()) is None


def test_backfill_skips_closed_case(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            await _seed_case(conn, "closed", ["ip:203.0.113.20"], status="closed")
            alert_id = await _seed_alert(conn, agent, "203.0.113.20")
        await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            return (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar()

    assert _run(go()) is None


def test_backfill_respects_excluded_addresses(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO platform_settings (key,value,is_secret) "
                "VALUES ('case_ioc_exclusions','192.0.2.77',false)"
            ))
            agent = await _seed_agent(conn)
            await _seed_case(conn, "excl", ["ip:192.0.2.77"])
            alert_id = await _seed_alert(conn, agent, "192.0.2.77")
        await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            return (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar()

    assert _run(go()) is None


def test_backfill_leaves_already_assigned_alerts_alone(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            original = await _seed_case(conn, "original", ["ip:203.0.113.30"])
            await _seed_case(conn, "other", ["ip:203.0.113.30"])
            alert_id = await _seed_alert(conn, agent, "203.0.113.30")
            await conn.execute(text("UPDATE alerts SET case_id = :c WHERE id = :i"),
                               {"c": original, "i": alert_id})
        await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            return (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar(), original

    linked, original = _run(go())
    assert linked == original


def test_backfill_runs_only_once(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import MARKER_KEY, backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            await _seed_case(conn, "campaign", ["ip:203.0.113.40"])
            await _seed_alert(conn, agent, "203.0.113.40")
        first = await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            await _seed_alert(conn, agent, "203.0.113.40")
        second = await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            marker = (await conn.execute(
                text("SELECT value FROM platform_settings WHERE key = :k"), {"k": MARKER_KEY}
            )).scalar()
            unlinked = (await conn.execute(
                text("SELECT count(*) FROM alerts WHERE case_id IS NULL")
            )).scalar()
        return first, second, marker, unlinked

    first, second, marker, unlinked = _run(go())
    assert first == 1
    assert second == 0
    assert marker == "1"
    assert unlinked == 1


def test_backfill_ignores_alerts_without_source_ip(env):
    from app.core.database import engine
    from app.services.alert_case_backfill import backfill_alert_case_id

    async def go():
        await _reset()
        async with engine.begin() as conn:
            agent = await _seed_agent(conn)
            await _seed_case(conn, "campaign", ["ip:203.0.113.50"])
            alert_id = await _seed_alert(conn, agent, None)
        await backfill_alert_case_id(engine)
        async with engine.begin() as conn:
            return (await conn.execute(
                text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id}
            )).scalar()

    assert _run(go()) is None
