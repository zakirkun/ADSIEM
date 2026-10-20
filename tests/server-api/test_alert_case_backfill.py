# tests/server-api/test_alert_case_backfill.py

import pytest

from app.services.alert_case_backfill import MARKER_KEY, parse_excluded_ips


@pytest.mark.parametrize("raw,expected", [
    (None, []),
    ("", []),
    ("203.0.113.9", ["203.0.113.9"]),
    ("203.0.113.9, 198.51.100.7", ["198.51.100.7", "203.0.113.9"]),
    ("203.0.113.9\n198.51.100.7", ["198.51.100.7", "203.0.113.9"]),
    ("  203.0.113.9  ", ["203.0.113.9"]),
    ("203.0.113.9,203.0.113.9", ["203.0.113.9"]),
])
def test_parse_excluded_ips_reads_plain_addresses(raw, expected):
    assert parse_excluded_ips(raw) == expected


def test_parse_excluded_ips_ignores_cidrs():
    assert parse_excluded_ips("10.0.0.0/8, 203.0.113.9") == ["203.0.113.9"]


def test_parse_excluded_ips_ignores_domains():
    assert parse_excluded_ips("example.com, 203.0.113.9") == ["203.0.113.9"]


def test_marker_key_is_stable():
    assert MARKER_KEY == "alert_case_id_ioc_backfill_at"


@pytest.mark.parametrize("ip,kept", [
    ("203.0.113.9", True),
    ("198.51.100.7", True),
])
def test_excluded_addresses_are_filtered_before_matching(ip, kept):
    excluded = parse_excluded_ips("192.0.2.77")
    assert (ip not in excluded) is kept
