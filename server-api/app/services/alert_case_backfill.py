# server-api/app/services/alert_case_backfill.py
"""One-time linking of pre-existing alerts to the campaign case that names their IP.

A case keeps its attacker IOCs in ``ioc_data->ioc_keys`` as ``ip:<addr>`` (also
hash/domain/url). Alerts created before ``alerts.case_id`` existed only carry
``source_ip``, so the IP keys are the one available link. Kept out of main.py so
it can be tested without importing the app.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

MARKER_KEY = "alert_case_id_ioc_backfill_at"

_SELECT_CANDIDATES = """
WITH candidate AS (
    SELECT a.id AS alert_id, c.id AS case_id,
           ROW_NUMBER() OVER (PARTITION BY a.id ORDER BY c.created_at) AS pick
      FROM alerts a
      JOIN cases c
        ON c.ioc_data -> 'ioc_keys' ? ('ip:' || a.source_ip)
     WHERE a.case_id IS NULL
       AND a.source_ip IS NOT NULL
       AND COALESCE(c.ioc_data ->> 'merged_into', '') = ''
       AND c.status <> 'closed'
       AND NOT (lower(a.source_ip) = ANY(:excluded))
)
UPDATE alerts a
   SET case_id = candidate.case_id
  FROM candidate
 WHERE a.id = candidate.alert_id
   AND candidate.pick = 1
RETURNING a.id
"""


def parse_excluded_ips(raw: str | None) -> list[str]:
    """IPs from the ``case_ioc_exclusions`` setting, ignoring CIDRs and domains."""
    if not raw:
        return []
    out = set()
    for item in raw.replace("\n", ",").split(","):
        value = item.strip().lower()
        if not value or "/" in value:
            continue
        if value.replace(".", "").isdigit():
            out.add(value)
    return sorted(out)


async def backfill_alert_case_id(engine: AsyncEngine) -> int:
    """Link unassigned alerts to the case holding their source IP. Returns the count.

    Runs once: a platform_settings marker keeps it off every later startup.
    Skips merged and closed cases, and any address the operator excluded from
    grouping, so a shared NAT/proxy IP cannot pull unrelated alerts into a case.
    """
    async with engine.begin() as conn:
        done = (await conn.execute(
            text("SELECT 1 FROM platform_settings WHERE key = :k"), {"k": MARKER_KEY}
        )).first()
        if done:
            return 0

        excluded_row = (await conn.execute(
            text("SELECT value FROM platform_settings WHERE key = 'case_ioc_exclusions'")
        )).first()
        excluded = parse_excluded_ips(excluded_row[0] if excluded_row else None)

        updated = (await conn.execute(
            text(_SELECT_CANDIDATES), {"excluded": excluded}
        )).all()

        await conn.execute(
            text("INSERT INTO platform_settings (key, value, is_secret) "
                 "VALUES (:k, :v, false) ON CONFLICT (key) DO NOTHING"),
            {"k": MARKER_KEY, "v": str(len(updated))},
        )
        return len(updated)
